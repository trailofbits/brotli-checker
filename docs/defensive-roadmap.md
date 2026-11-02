# Defensive scanner roadmap

This roadmap records the implemented defensive evidence layers and remaining
qualification work. The full skill uses pinned analysis backends and automatic
FLIRT. Dependency-free execution remains available, with explicit gaps when a
required backend is unavailable. Recognition never substitutes for patch proof.

## Evidence invariants

- Keep component recognition, patch state, provider selection, shipment, reachability, and exploitability separate.
- Attach patch state only to the source, code, package, or vendor assertion that established it. Relations do not transfer `fixed` to a consumer or deployment.
- Analyze only supplied local scope. Do not execute targets or loaders, invoke `ldd`, search host libraries, upload artifacts, or refresh advisories implicitly.
- Bound parser work, candidate verification, graph nodes/edges, and output; keep large-file reads streamed or sparse rather than adding arbitrary default file-size caps. Malformed, unsupported, or truncated evidence produces a coverage gap.
- Preserve stable-fd sparse access and streamed hashing for large regular files.

## Current foundation

- Exact source identities and conservative modified-source checks.
- Language-scoped source/FFI and dependency leads.
- Relocation-masked ELF code references plus separate automatic FLIRT function recognition, neither of which proves runtime use.
- ELF import/export and constant-version metadata.
- Compiler-independent decoder-table recognition; table evidence is not patch state.
- Bounded ELF fragment disassembly with no automatic semantic verdict.
- ZIP/TAR/gzip/bzip2/XZ/ar/DEB/RPM/cpio/zstd traversal, OCI final-filesystem views,
  explicit unsupported-format gaps, archive/text budgets, and per-copy JSON evidence.

## Ordered milestones

### 1. In-scope ELF provider graph (`M`)

**Implementation:** Parse bounded `DT_NEEDED`, `DT_SONAME`, `DT_RUNPATH`, and `DT_RPATH` evidence, then relate importers to compatible provider artifacts only after all supplied roots are scanned. Expand audited `$ORIGIN` components inside the same filesystem or archive namespace. Report unique candidate, ambiguous, missing, incompatible, and unsupported-token states; never claim loader selection.

**Acceptance:** The existing sibling-DSO fixture resolves `$ORIGIN/../lib` to one candidate; executable-only, duplicate-SONAME, wrong-ABI, escaping-path, RUNPATH-vs-RPATH, archive, and fixed-provider controls remain conservative.

### 2. Seeded xrefs and local function graph (`H`)

**Implementation:** Feed symbols, unwind/function-start metadata, decoder-table offsets, FLIRT results, exact matches, and trusted explicit ranges into one bounded graph. Prefer relocation-backed data references, then decode bounded executable ranges for PC-relative references and direct call/tail-call edges. Preserve unresolved indirect transfers. Use the graph to select triage ranges and associate patch roles with decoder copies, not to assign patch state by itself.

**Acceptance:** Real stripped/LTO table positives locate table users; distinct copies remain distinct; ICF/shared helpers remain shared; unknown relocation or ISA modes and exhausted budgets are gaps; encoder/table-only controls do not gain a patch verdict.

### 3. Verified debug companions (`M`)

**Implementation:** Resolve only supplied ELF build-ID/`.gnu_debuglink`, Mach-O UUID, and PE PDB GUID/age companions. Use verified companions for function bounds, names, and source locations. Never follow embedded absolute paths or contact symbol servers automatically.

**Acceptance:** Mismatched, duplicate, missing, and split debug data stay unresolved; debug names alone cannot establish fixed code.

### 4. Structured provenance and distro backports (`H`)

**Implementation:** Parse bounded CycloneDX/SPDX components, hashes, relationships, and completeness instead of matching one text line. Add same-root dpkg/apk ownership, then an independently reviewed RPM path. Accept explicit dated Debian, Ubuntu, and Red Hat advisory snapshots with native package-version ordering. Distinguish name-only, package-ID, artifact-hash-bound, and verified-attestation evidence.

**Acceptance:** Hash and dependency edges survive parsing; incomplete BOMs say so; host metadata cannot classify a container file; feed source/date/digest and package scope are retained; vendor-fixed packages do not clear embedded copies.

### 5. Loader-aware PE and Mach-O (`H`)

**Implementation:** First validate mapped sections, imports/exports, dependencies, relocations, and platform function metadata. Scope stable tables to mapped data. Official paired Windows/macOS wheels are hash-pinned loader/table fixtures.
FLIRT target ownership now supports explicitly format-bound PE and Mach-O executable
ranges, including independent universal slices; ELF profiles cannot silently cross
formats. A native hosted-runner pipeline builds reviewed affected/fixed MSVC,
clang-cl, and Apple-clang pairs, normal and LTCG/LTO controls, signed universal
Mach-O controls, exact post-link patch-role patterns, and opposite-state tests.
**Qualification:** hosted Windows and macOS builds completed; their paired
normal-library and post-link profiles, opposite-state and mixed-copy controls,
slice ownership, PDB packets, and per-slice dSYM packets were independently replayed.
Validated normal, Windows LTCG, and Apple ThinLTO profiles are packaged. Exact
post-link artifact assertions are kept separate from function recognition. Complete
native function populations remain provenance only until one decoder copy is bound;
the scanner does not combine matching functions scattered across copies into a fix.

**Acceptance:** Resources and nonloaded data do not count as decoder use; fat slices and CPU subtypes stay separate; unsupported fixups, encryption, arm64e, or linker modes remain gaps; fixed evidence never crosses artifacts or slices.

### 6. Module-aware WebAssembly (`M-H`)

**Implementation:** Parse bounded imports, exports, types, functions, code, data, data count, and name sections. Scope tables to data initializers and recover direct function-index calls while preserving indirect-table uncertainty. Retain the implementation family: C-to-Wasm and independent Rust/JS ports need distinct patch evidence.

**Acceptance:** Custom-section lookalikes do not count; malformed LEB/count/size inputs are incomplete; passive/active data is distinguished; no module is instantiated or executed.

### 7. CI evidence and comparison (`M`)

**Implementation:** Add a reproducibility envelope with scanner/advisory/catalog/feed digests, effective limits, optional-tool identity, findings, relations, and gaps. Render deterministic SARIF 2.1.0 as a view of canonical JSON. Compare reports only when roots, evidence catalogs, limits, and coverage are compatible. Offer explicit fail policies without changing default exit semantics.

**Acceptance:** New/unchanged/absent labels require a complete comparable scan; skipped prior paths are never reported resolved; fingerprints exclude unstable line/byte offsets; no renderer uploads data or suppresses current evidence.

### 8. Payloads and adversarial assurance (`S-H`, incremental)

**Implementation:** Add regular ar/DEB traversal first (`S-M`), then explicit optional zstd, RPM/cpio, and OCI final-filesystem/whiteout support (`H`). Expand malformed format, mixed-copy, partial-backport, compiler/linker, and package-provenance corpora. Use development-only coverage-guided fuzzing for parsers and graph logic.

**Acceptance:** Members never escape to host paths; expansion and layer budgets remain enforced; historical OCI layers are not called shipped; parser failures are deterministic gaps; production scanning keeps target execution disabled.

## Tool choices

- Prefer small core parsers for owned evidence and sparse reads.
- Optional [Capstone](https://www.capstone-engine.org/arch.html) may decode bounded fragments only in audited ISA modes.
- [GNU objdump](https://sourceware.org/binutils/docs/binutils/objdump.html) or [LLVM objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html) remains a trusted, time/output-bounded triage backend.
- [LIEF](https://lief.re/doc/latest/intro.html) is useful as an optional parser or differential test oracle, not an implicit core dependency.
- [Ghidra headless](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md) is an analyst-directed export backend for hard cases, never an automatic normal-scan step.
- [Syft](https://oss.anchore.com/docs/guides/sbom/getting-started/) output may be consumed as a hash-bound sidecar; the scanner does not invoke it or upload its output by default.

Primary contracts: [ELF dynamic linking](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.dynamic.html),
[Microsoft PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[Apple Mach-O](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h),
[WebAssembly binary modules](https://webassembly.github.io/spec/core/binary/modules.html),
[CycloneDX](https://cyclonedx.org/specification/overview/),
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).

## Operational entry points

See [structured analysis](../skills/brotli-checker/references/analysis.md) for flags,
namespace rules, local vendor snapshot schema, and remaining format limitations.
The implementation does not claim general semantic patch verification or automatic
runtime loader selection. Explicit PDB exports provide verified names/bounds, not
a complete native PDB parser. Offline attestations authenticate predicate claims;
they do not independently establish build truth, patch state, or signer freshness.


## Resolution paths implemented in the follow-up

These paths improve evidence, not the meaning of a clean scan. Unmatched targets
are not declared safe, and partial recognition is not a fixed-copy verdict.

| Boundary | Implemented path | Remaining support boundary |
| --- | --- | --- |
| Multiple embedded native copies | Post-link FLIRT groups require all patch roles at one reviewed relative layout, with exact bytes including direct-call displacements; mixed-copy controls reject unions | One fixed component cannot clear unmatched copies; arbitrary reordered/inlined layouts need new qualification |
| LTO/LTCG transformation | Source-bound paired native builds, verified PDB/dSYM bounds, opposite-state and mixed-copy controls, separate exact-artifact assertions | Compiler/linker transformations are qualified individually, never inferred from build metadata |
| ARM/Thumb graph modes | Odd function addresses and `$a`/`$t`/`$d` intervals establish mode; conflicts remain poisoned; direct branches, literals, and audited MOVW/MOVT pairs add edges | Stripped mode/boundary provenance, PIC/GOT sequences, IT uncertainty, and indirect transfers can remain unresolved |
| Other ELF graph ISAs | `--graph-triage` imports exact-target bounded triage packets; x86 and standard PPC64 direct branch targets are byte-derived | Unknown instruction semantics and unsupported ABI modes remain explicit gaps; text cannot invent edges |
| Mach universal dSYM/source lines | Explicit trusted dwarfdump export, bound to full artifact/companion hashes and each slice's UUID, architecture, offset and hash | Missing/split/unsupported debug descriptions stay unresolved; embedded source paths are never opened |
| Wasm function identity | Canonical direct-call/data-bound identities and partial family candidates; paired Google C modules independently source-rebuilt to exact npm bytes | Only qualified whole-module or full non-custom-section identity establishes patch state; population unions and independent ports do not |
| Runtime provider/reachability | `--runtime-trace` joins explicit positive observations by namespace, path, and artifact SHA-256 | Collector claims need independent review; no static loader guesses, negative trace inference, or attacker-control upgrade |
| Sigstore/JSF/freshness | Isolated maintained offline Sigstore verifier, pinned identity/issuer/trust configuration; JSF Ed25519/JCS; explicit evaluation and expiry windows | Offline policy cannot discover new revocations or establish predicate truth; unsupported signature profiles fail closed |
| Parser differential assurance | Isolated bounded scanner/LIEF workers plus explicit LLVM oracle, retained valid/malformed fixtures, replay CI | Agreement is fixture-scoped; disagreements and resource limits are investigation evidence, never scanner verdicts |

### Qualification evidence

- Windows [41482274418](https://github.com/trailofbits/brotli-checker/actions/runs/41482274418)
  (successful Windows job) and macOS
  [41493301081](https://github.com/trailofbits/brotli-checker/actions/runs/41493301081)
  independently qualified paired MSVC/clang-cl LTCG and Apple ThinLTO builds.
  Packaged evidence now contains 3,567 records / 376 profiles, including eight
  copy-bound post-link profiles, and twelve exact native identities. All six
  transformed artifacts passed real CLI checks and own/opposite/mixed-copy controls.

- WebAssembly run [41485529110](https://github.com/trailofbits/brotli-checker/actions/runs/41485529110)
  rebuilt reviewed Google Brotli 1.2.0/1.2.1 commits with the pinned Emscripten
  image and exact builder archives. Both outputs byte-reproduced the reviewed
  npm modules. Exact, opposite-state, custom-only, modified-data, and mixed-population
  controls were replayed; the generated catalog retains the build commit/run.
- Actual retained ARM and Thumb binaries exercise symbol/mapping mode provenance;
  stripped controls retain unavailable-boundary gaps. A retained LLVM-built PPC64LE
  fixture checks direct call/tail targets and malicious disassembly-text controls.
- Scanner, LIEF 1.0.0, and LLVM 22.1.8 agree on the retained valid ELF, malformed PE,
  and PPC64LE fixtures. Dedicated CI retains the reports, including nonpasses.
- The maintained Sigstore 4.2.0 CLI passes a pinned official bundle conformance
  fixture and rejects digest replacement. It is isolated because its cryptography
  dependency range conflicts with the scanner's pinned analysis dependency.

See [runtime observations](../skills/brotli-checker/references/runtime-evidence.md),
[attestations](../skills/brotli-checker/references/attestations.md),
[parser assurance](../skills/brotli-checker/references/parser-assurance.md), and
[function signatures](../skills/brotli-checker/references/flirt.md) for operational
contracts and limitations. Native transformed-profile qualification is recorded
separately in the generated catalogs and hosted validation evidence.
