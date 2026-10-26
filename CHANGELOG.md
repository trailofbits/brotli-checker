# Changelog

## Unreleased

- Recognize compiler-independent Brotli decoder table signatures in binaries,
  including stripped/LTO builds. Report recognition strength and table offsets
  separately from patch state; encoder dictionaries alone do not qualify.
- Scope ELF table evidence to load segments, report malformed-layout gaps, and
  preserve bounded streaming/sparse access. Non-ELF table evidence is explicitly
  file-content-only, without loader or execution claims.

- Add 14 reviewed Go/Rust source fingerprints for analogous block-switch
  error-handling fixes, with explicit implementation and upstream-fix provenance.
  Do not infer the C advisory's memory-corruption impact for independent ports.
- Collect bounded language-import, decoder API, and FFI source leads across
  Python, JVM, .NET, Rust, Go, Ruby, PHP, and JavaScript/WASM integrations.
  Preserve implementation uncertainty and distinguish native bindings from ports.
- Extend dependency collection to Python setup/Pipfile/requirements variants,
  Ruby, Composer, and .NET metadata; filter the new structured formats by
  dependency fields rather than descriptive prose.
- Expand source-call discovery names and add an ecosystem provider/reachability
  guide with primary-source examples. Import aliases and dynamic providers still
  require review; wrapper versions do not establish the native decoder version.

- Expand the packaged ELF catalog from 336 to 432 references while preserving
  every prior entry: add 72 scope-aware GCC references for x86-64/AArch64
  function-section builds linked with garbage collection, plus 24 complete
  LoongArch GCC 14 references.
- Require all eight patch-bearing decoder roles and recognized emitted
  helper/clone/cold sections for a scoped code match, while allowing linker GC
  to discard unrelated public APIs. Record the reference scope and
  function-to-fragment population in match evidence; missing roles remain
  unknown.
- Add opt-in QEMU runtime checks for the ELF build matrix, covering one-shot and
  streaming decode, decoder versions, normal/stripped/sectionless artifacts,
  linker-GC and missing-role controls, paired affected/fixed references, and
  explicit candidate/packaged-profile compatibility reporting.
- Report opaque SquashFS, Snap, AppImage, and ASAR payloads as coverage gaps,
  preserving outer ELF evidence for AppImage without extraction. Route
  Dockerfile/Containerfile variants and `.bzl` through dependency-lead analysis.
- Report source-parser/grammar-provider failures as incomplete JSON evidence,
  and normalize whitespace in explicitly supplied discovery symbols.
- Validate MIPS instruction modes before raw disassembly; unsupported modes
  remain incomplete rather than being interpreted as classic r2 instructions.
- Write gzip catalogs with a fixed compression level and canonical header
  metadata across supported Python versions.

## [0.2.0] - 2026-10-23

- Expand packaged ELF decoder fingerprints to 336 profiles across x86-64, x86,
  ARM/Thumb, AArch64, RISC-V64, PowerPC64LE, s390x, MIPS32/64 in both byte orders,
  and LoongArch64. Coverage remains compiler/profile-specific.
- Support ELF32/64 and both byte orders in code matching, metadata
  inspection, and bounded disassembly triage, including split executable sections
  and audited linker instruction rewrites. RISC-V32 and big-endian PowerPC64 are
  parsed but have no packaged fingerprints.
- Add reference catalog merging and deterministic gzip storage.
- Add checksum-pinned upstream known-answer fixtures and parameterized regression
  tests. Downloaded dependencies stay outside git. Increase the mutation score
  from 84.64% to 85.91% with matching timeouts, operators, and CLI exclusions.

## [0.1.1] - 2026-10-23

- Add bounded Trailmark discovery of source callers and decoder call paths,
  preserving unknown results for unresolved calls and runtime reachability.
- Restore the mutation test gate and expand binary boundary regression coverage.
- Fix binary prefix checks beyond the end of a file.

## [0.1.0] - 2026-10-23

- Initial release of the Brotli Checker skill for Claude Code and Codex.
- Include offline source and dependency inventory, source fingerprints, AArch64
  ELF decoder fingerprints, and bounded binary disassembly review.

[0.2.0]: https://github.com/trailofbits/brotli-checker/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/trailofbits/brotli-checker/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/trailofbits/brotli-checker/releases/tag/v0.1.0
