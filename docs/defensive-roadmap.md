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
**Remaining qualification:** paired affected/fixed MSVC, clang-cl, and Apple-clang
patch-code references, including signed/LTCG/LTO/dead-strip/ICF controls. The local
clang-cl probe lacks MSVC/UCRT headers and the Apple target lacks its SDK. Neither
ELF references nor table matches are presented as replacements for that corpus.

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
The implementation does not claim general semantic patch verification, full PDB
symbol decoding, verified attestations, or automatic runtime loader selection.
