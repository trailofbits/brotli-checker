---
name: brotli-checker
description: Check whether an app or project needs a Brotli security update for CVE-2026-111497, explain the result in plain language, and give practical next steps. Find bundled copies and investigate whether the running app uses them.
---

# Check whether an app needs a Brotli update

Help someone who is not a security expert answer: "Does my app need an update,
and what should I do next?" They should be able to say "check this project" or
give a website address without knowing library versions, build details, or the
CVE number. Gather technical evidence yourself; translate it into a short,
actionable answer.

Assess CVE-2026-111497 for the requested source tree, application, or deployment.
Finding vulnerable source establishes source containment. Build selection,
shipment, attacker-controlled input reaching that decoder, and exploitability
are separate conclusions. Keep a result for each copy; one fixed copy cannot
clear other copies.

## Gather evidence

For "this project", start with the current project folder and discover its
application, dependencies, and deployment files. Use the supplied folder or
server access when available. Collect versions and package information with
trusted, read-only inspection tools; do not run application code or scripts
from the target. Do not make the user supply technical facts you can inspect.

Identify the target revision, build/platform, deployed artifact or container
digest, and the installation actually serving the application when available.
If only a URL is supplied, explain that headers and Brotli response support
cannot identify the decoder or its patch status. Say "I can't confirm this from
the website address alone" and give a short message the user can send to their
hosting provider asking it to check and update the app's Brotli decoder. If
the conversation already provides local/server access, use it. Ask only for
missing access or a target that cannot be inferred. Do not send malformed
streams or exploit probes.

From this skill's directory, use Python 3.14 with the pinned analysis backends.
The core can run on Python 3.12-3.15 without them, but unavailable analysis is a
coverage gap, not an equivalent scan.
Use JSON internally for the evidence; the default text output is for people:

```sh
uv run --python 3.14 --with python-flirt==0.10.2 --with capstone==5.0.9 \
  --with pyelftools==0.33 --with zstandard==0.25.0 python scripts/brotli_inventory.py /absolute/target --json
```

It reads files and bounded ZIP/JAR/WAR/wheel, TAR, gzip, bzip2, XZ, ar/DEB,
RPM/cpio, and Zstandard payloads without extracting them to target paths or
executing target code. Known signatures identify renamed archives. OCI/Docker
save images use final-filesystem whiteout semantics; historical layer records
are not evidence of shipment. Unsupported encodings and budget exhaustion are
coverage gaps. It checks eligible file bytes
against source fingerprints, identifies modified C decoder patterns, and records
dependency, native/Wasm, and JavaScript/TypeScript fetch/Undici candidates.
Fetch references include source locations; they are heuristic leads, not
confirmed Node calls or attacker-controlled inputs. For supported ELF32/ELF64 targets it also
matches compiled decoder text, including stripped and statically linked code.
Dependencies, build outputs, and hidden directories
are included; `.git` is excluded. Read its coverage gaps. It does not scan an
entire host, resolve remote dependencies, follow symlinks, prove whole-application patch
status, or establish an absence of Brotli. Supply extracted image filesystems
or additional artifact roots as needed. Filesystem symlink targets visited
directly do not add a gap; other targets still need checking. If a resource limit
is reached, scan a smaller relevant folder or adjust the limit shown by `--help`.
Regular files have no default per-file or total byte cap. ELF analysis uses
sparse offset reads; full-artifact SHA-256 is streamed. Archive expansion is
separately budgeted at 8 GiB/member or stream and 64 GiB total; override with
`--max-expanded-bytes` and `--max-total-expanded-bytes` as needed. Optional
`--max-file-bytes` and `--max-total-bytes` still impose explicit input caps.

For independently obtained upstream versions, optional flags are:

```sh
python3 scripts/brotli_inventory.py --brotli-version 1.2.0 --json
python3 scripts/brotli_inventory.py --node-version 24.22.0 --json
```

These flags assess a supplied version string, not an installed or running build.
Never pass a wrapper package's version as the embedded Brotli version. Version
warnings allow vendor backports; prereleases, vendor suffixes, and branches
outside the snapshot's rules remain unknown. Exit 1 means affected-source or
version evidence; 3 means review/unknown; 0 means only the reported items meet
a known source fingerprint or upstream fixed-version rule; 2 means CLI error.
The helper never certifies the application safe.

For ELF code findings, inspect `evidence.code_matches`: source/object hashes,
compiler/flags, state, and file offset. `vulnerable_code_match` and
`mixed_code_matches` warrant update review (exit 1). `fixed_code_match` concerns
only matched decoder code, leaves other copies unresolved, and does not by itself
produce exit 0. Version strings/imports do not determine code state. Matching
excludes relocated address fields and does not verify their targets or referenced
data or associate separately matched executable sections. Packaged references cover
x86, x86-64, ARM/Thumb, AArch64, RISC-V64, PowerPC64 little-endian, s390x,
MIPS32/64 in both byte orders, and LoongArch64. The 432 references cover `-O2`/`-O3`
PIC/non-PIC builds of three affected/fixed release pairs with GCC 14.2, the
original AArch64 GCC 16.2.1 builds, and Clang 19 LoongArch builds. LoongArch also
has GCC 14.2 references built with `-mno-relax` against a real LoongArch glibc
sysroot. The two Loong toolchains have distinct header/sysroot provenance; inspect
`build_note`, `headers_sha256`, compiler, and flags rather than treating the ISA as
the build identity.

For x86-64 GCC 14.2, AArch64 GCC 14.2, and AArch64 GCC 16.2, the catalog also
covers `-ffunction-sections -fdata-sections` linked with section garbage
collection. These entries have `code_scope: patch_bearing_sections_v1` and method
`relocation_masked_patch_sections`. They require exact matches for every emitted
section owning literal, command, and distance block-switch handling, all safe
variants, and normal/safe command processing, plus recorded emitted helpers. They
intentionally do not require unrelated public APIs which the linker may discard.
A fixed scoped match establishes only the recorded patch-bearing population, not
the whole decoder, unused APIs, another copy, or runtime selection. Missing any
required role prevents that reference from matching. Paired controls reject
opposite-state code, and matching both states reports a mixed result. This does
not establish that separately matched fragments belong to one decoder copy.

Other compilers/options require corresponding trusted references via
`--code-references`. Cross-translation-unit LTO can rewrite and reorder the final
code beyond both complete and function-section pre-link identities; keep those
binaries unknown unless reviewed post-link evidence or bounded disassembly closes
the gap. No match remains unknown; a supported target with no references produces
an explicit coverage gap. Do not present this as compiler-independent semantic or
CFG patch verification.

The inventory also reads bounded ELF symbol tables without executing the target.
It distinguishes decoder API definitions from imports. For an exactly defined
`BrotliDecoderVersion`, it accepts only supported straight-line constant-return
instruction forms. A reported old supported-branch version is
`potentially_vulnerable` and produces the normal exit 1 unless stronger evidence
already applies. A reported fixed version is metadata only and never clears the
binary. Code-reference matches remain code-identity evidence; metadata does not
upgrade an unmatched binary to `fixed_code_match`.

For `decoder_import_candidate`, statically inspect the importer and every
in-scope provider candidate before triage. Use a trusted `readelf` to record
`DT_NEEDED`, `DT_RPATH`/`DT_RUNPATH`, and undefined decoder symbols, then scan the
actual regular provider files from the supplied application, image, or deployment
root. Never run `ldd`, invoke a dynamic loader, or shell-evaluate `$ORIGIN` or
other path tokens. A needed name, RUNPATH, SONAME, host library, or one fixed
provider does not prove which file the deployed loader selects. Keep selection
and reachability unknown until deployment-specific evidence closes them. See
[dynamic ELF providers](references/reachability.md#dynamically-linked-elf-providers).

For `decoder_data_signature`, use the [stable signature guide](references/binary-signatures.md).
The full command table or complete code-length table set is stronger recognition
evidence than a string, but occurs in both affected and fixed builds. Report
`detection_status` separately from patch state. Preserve file offsets, ELF virtual
addresses, and mapping scope; locate code cross-references to these **data** tables,
then inspect bounded executable ranges and error propagation. Do not disassemble
table bytes as if they were code or promote a table match to an affected/fixed
verdict. PE/Mach-O/Wasm table evidence is scoped to validated mapped data or data
initializers; universal Mach-O slices remain separate. These formats do not yet
have a paired patch-code reference corpus. Dictionary-only
presence does not establish a decoder, and unmatched signatures do not prove absence.

For unmatched ELF code, use the automatic [FLIRT function-recognition workflow](references/flirt.md)
to obtain individual function names and bounded code windows from trusted
patterns. It runs by default; `--no-flirt` is an explicit speed/coverage tradeoff.
Use Python 3.12-3.14 and the pinned backend as documented. Inspect `flirt.matches`, `ambiguous_matches`, gaps, and
`ambiguity_complete`. Do not equate `source_state_provenance` with target patch
state or discard table/symbol/code evidence when FLIRT disagrees or misses.
Use recognized windows for bounded disassembly, then verify actual error
propagation and caller/callee targets. Unsupported reference constraints are
rejected rather than assumed satisfied. The scanner does not download patterns
or execute the target.

Read [structured analysis](references/analysis.md) for provider and function graphs,
verified debug companions, hash-bound SBOMs, same-root package ownership, vendor
snapshots, SARIF, and comparable report diffs. Function/data-reference edges are
triage evidence, not a semantic fix proof. Use `--deployment-root` for a supplied
image filesystem and `--debug-file` only for explicitly supplied companions.
Embedded debug paths are never followed. Package/vendor assertions and provider
relations never transfer fixed status to another artifact or embedded copy.

For an unresolved local ELF with decoder table, name, symbol, version, or code evidence,
collect bounded disassembly for model review instead of stopping at a generic
unknown. Do not disassemble every unrelated ELF. Run this only with a trusted
local `objdump`; the helper rejects target
symlinks, streams the original artifact hash, reads ELF structures by offset,
and passes only bounded code-fragment snapshots to `objdump`. It never executes
or loads target code and does not copy the full target. Detected input mutation
makes the report incomplete:

```sh
python3 scripts/brotli_binary_triage.py /absolute/target > triage.json
```

The default mode selects defined `Decode*BlockSwitch`,
`SafeDecode*BlockSwitch`, and `ProcessCommands*` symbols, with
`BrotliDecoderDecompressStream` as a public-symbol fallback. It records the target
SHA-256, exact commands, selected scope, limits, symbols, and bounded output.
Fragment hashes and source offsets bind the assembly to selected bytes; raw
objdump output uses `.data`, not original section names. Resolve numeric call
targets using the reported symbol addresses and original ELF scope. Exit
0 means evidence collection completed, not that the binary is fixed. Exit 3 means
the evidence is incomplete. For stripped code, use only a range derived from
trusted link/map or scanner evidence, for example `--file-offset OFFSET --length
BYTES`, or `--start-address START --stop-address STOP [--section .text]`. Do not
guess a range from a string location. Symbol and explicit-range modes both enforce
`--max-range-bytes`; raise that bound deliberately when a trusted symbol is larger.
If a trusted tool or defensible code scope is unavailable, keep the result unknown
and state that missing evidence and the exact next request.

Review triage evidence against the reviewed affected and fixed `decode.c` sources,
not against mnemonic or string presence. Trace each literal, command, and distance
block-switch path. The fixed design returns `BrotliDecoderErrorCode`, produces
`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` for the invalid switch, and propagates
that status through `ProcessCommands*`; the old design uses boolean/void handling
that can lose the specific failure. Confirm the safe and non-safe callers and the
error propagation, not merely a helper body. A version constant, import/export,
function name, or nearby error string cannot establish the fix. If optimization,
inlining, missing callers, output limits, multiple copies, or unfamiliar control
flow prevents that trace, preserve `unknown`. One fixed-looking range never clears
other copies or establishes runtime use.

For artifact hashes and rollout inventory, optionally use:

```sh
python3 scripts/brotli_binary_inventory.py /absolute/target
```

Its exit codes differ: 1 means inventory candidates (including fixed matches),
3 means coverage gaps, and 0 means no candidates/gaps, not that an app is safe.

End-of-life Node.js versions get supported-branch upgrade advice, while decoder
patch status remains unknown (exit 3) without build or vendor evidence.

Validation has covered decoder source references, synthetic ELF/packaging
fixtures, an opt-in suite for locally compiled stripped ELF artifacts, and a
benign loopback test of built-in Node fetch response decompression. No deployed
application or production binary's patch state was validated, and no malformed
or exploit payload was executed. The benign fetch test establishes a decoding
route, not CVE triggerability or exploitation. Do not describe source
classification as an end-to-end test of a vulnerable app.

The packaged function-section profiles were additionally validated with real
linked `--gc-sections` builds for x86-64 GCC 14.2, AArch64 GCC 14.2, and AArch64
GCC 16.2 across all six releases and four optimization/PIC profiles. LoongArch
GCC 14.2 complete references received the same 24-case linked/QEMU matrix. These
benign executions confirm ordinary decoder operation and reference recognition;
they are not malformed-stream, reachability, or vulnerability tests.

## Establish patch status and reachability

Read [the advisory and detection reference](references/advisory.md) for source
provenance, fixed branches, backports, and detection limits. Verify current
vendor guidance if online research is available; otherwise date the assessment
to the packaged snapshot and flag that advisory freshness is unverified.

Inspect lockfiles, submodules, downloaded build inputs, native libraries inside
archives, linking configuration, SBOMs, and the shipped binary. Check all build
variants relevant to the deployment. Do not equate a dependency declaration or
an inventory entry with compilation or shipment. Stripped/static binaries need
build provenance, vendor evidence, or binary analysis; absence from a dynamic
library listing is insufficient. A fixed OS library does not fix embedded copies.

When relevant source is available, use Trailmark to accelerate discovery of
decoder/fetch calls and their callers. From this skill's directory, run the
packaged helper with uv, which installs its pinned Trailmark 0.7.0 dependency:

```sh
uv run --script scripts/brotli_source_discovery.py /absolute/source > discovery.json
```

Choose the relevant source subtree; initial parsing is not resource-bounded.
The first use may download Trailmark and its parser grammars. Do not substitute
an unverified ambient `trailmark` command or run tools supplied by the target.
The helper reads source without importing or executing the target. Keep the
inventory scan: Trailmark skips dependencies, build outputs, and hidden folders,
and can omit top-level JavaScript/TypeScript calls without a diagnostic.

Use `candidates[].call` and the `neighborhood` nodes, calls, and entrypoint tags
to prioritize source inspection. Preserve callsite locations, unresolved targets,
confidence, deferred callback edges, and `configured_by` provenance. Verify
bindings and callers in source; static confidence does not establish execution.
For a reviewed import alias or wrapper, rerun with `--symbol NAME`. This adds a
search target, not a verified binding. Repository `.trailmark` links and
entrypoint overrides are declarations that require independent review.

Exit 0 means evidence was collected, not that a decoder is fixed or reachable.
Exit 3 means collection is incomplete; inspect diagnostics, truncation, and gaps.
Missing paths or entrypoint tags never establish unreachability. If uv, parsers,
or supported source are unavailable, state the gap and continue manual review.
See [source discovery](references/reachability.md#trailmark-source-discovery)
for scope and review steps.

For each relevant surface, use [the reachability guide](references/reachability.md).
Trace the actual input entry point through middleware/wrappers to the selected
native decoder. Record configuration, authentication before decompression,
input ownership, and process boundaries. Consider inbound requests, outbound
responses, uploads and WOFF2/fonts, Java JNI stacks, workerd, and negotiated TLS
certificate compression. Pure Java/Rust implementations require their own
evidence; a language or algorithm name alone does not establish this C bug.

For Node.js apps, explicitly investigate built-in `fetch()`, `globalThis.fetch`,
and Undici wrappers, including attacker-controlled URLs and redirects. Automatic
Brotli response decoding can reach the native decoder without an explicit
Brotli dependency or `node:zlib` import. Establish the actual runtime's patch
state. The offline inventory records source-reference and dependency leads. Use
Trailmark's call evidence to find wrappers and callers, then verify fetch
bindings, URL ownership, and the running Node version yourself. Review source
locations and continue with the Node/fetch section of the reachability guide.
A fixed supplied version or standalone Brotli library does not clear an
unresolved runtime lead.

For non-C/C++ projects, use the [ecosystem integration guide](references/ecosystems.md).
The inventory's `decoder_source_candidate` findings collect language-scoped
imports and decoder API references with source locations. Their
`implementation_hint` is a lead based on expected upstream behavior, not proof
of the selected provider. Resolve aliases, optional dependencies, runtime
configuration, native extensions/JNI/FFI, and WASM assets before patch assessment.
Inspect bundled native code and deployment-specific shared providers; do not
substitute the review host's libraries. Independent Java, Rust, Go, and JavaScript
ports require their own implementation review, not the C library's version rules.
The registry includes separately reviewed exact Go/Rust source fingerprints for
analogous block-switch error fixes. Preserve their `issue_relation` and upstream
fix evidence; do not describe those matches as proof of the C corruption impact.
Keep wrapper version, decoder version, build selection, shipment, and input
ownership separate. Use reviewed local aliases via source discovery's `--symbol`
when its default names cannot follow a call. Absence of a lexical lead or graph
edge is not evidence that decoding cannot occur.

For Electron apps, use the guide's Electron section. Separate Chromium's
renderer/net/session fetch paths from Node fetch, and verify which decoder the
embedder links. A standalone Node version rule cannot classify a vendor Electron
build. Mach-O and ASAR packages require additional inspection. Benign Electron
and Slack renderer measurements confirmed local response decoding, while Slack's
shipped decoder patch status and attacker-controlled product paths remain unknown.
The offline scanner does not launch either application.

Report reachability as `confirmed`, `not_reachable_in_reviewed_configuration`,
or `unknown`, with paths/lines or deployment evidence. A negative conclusion
must name the exact configuration and reviewed paths. Missing evidence remains
unknown. Do not infer exploitability from reachability, CVSS, a crash, or a
third-party PoC.

## Explain the result and next action

Lead with a short answer that matches the evidence:

- "Update needed" when the app is confirmed to use an affected copy. State
  separately whether outside input can reach it.
- "Vulnerable Brotli source found" when affected code is present but its use by
  the running app is unknown. Say "We still need to check whether your app uses
  this copy." Do not label the whole app vulnerable from source presence alone.
- "Fix confirmed for the checked copy" when supported by verified evidence.
  State the scope; other copies and the running app may still need checking.
- "More information needed" when the result is inconclusive. Explain the
  specific missing information and who can obtain it.

Follow with what to do next. Name the affected component and the applicable
update when established, who should make it, and how to confirm the running app
has it. For a bundled copy, explain that the app must be rebuilt and deployed
again; updating the computer's shared library may leave that copy unchanged.
If action needs a maintainer or hosting provider, provide a short, ready-to-send
message with the specific finding and requested update/confirmation. Do not
send it yourself.

For several copies, use a small table: location, plain-language result, next
action. A fixed copy must not hide a vulnerable copy. Prioritize affected
shipped copies with confirmed untrusted input, then resolve other candidates.
State important unchecked files or missing running-app evidence in ordinary
language. An empty scan is inconclusive. Do not label it "safe" or "unaffected".

Keep the initial answer to a few sentences plus any useful short table. Avoid
raw status codes, hashes, long evidence columns, and unexplained terms such as
"shipment", "reachability", "JNI", or "provenance" in that answer. Preserve the
full per-copy evidence (patch confidence, build selection, shipped artifact,
input path, paths/lines, advisory date, and source/vendor links) for a maintainer
or a request for technical details. Do not make the user interpret a security
audit table to decide what to do.

Where an update cannot be deployed immediately, identify the specific receiving
decoder path that could be disabled and verify that boundary. Response encoding
settings alone do not establish that request, font, or certificate decoding is
disabled. Never present the community source inventory as vulnerable deployments.
