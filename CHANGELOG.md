# Changelog

## Unreleased

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
