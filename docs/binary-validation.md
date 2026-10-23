# Binary recognition and review validation

The scanner's evidence layers are deliberately separate:

1. Exact relocation-masked decoder text identifies a compiled reference.
2. Defined/imported ELF decoder symbols identify review leads. A supported
   constant-return version function can support an update warning, never proof
   that an entire binary is fixed.
3. Bounded objdump packets support model inspection of unresolved implementations.
   The model must trace the patch-bearing control flow and cite its evidence;
   packet collection is not an automatic patch verdict.

## Recognition coverage

On 2026-10-23, the Linux AArch64 corpus was scanned by both CLIs at their new
default byte budgets. Both inspected all 13 files without gaps. Results and input
SHA-256 hashes are in [binary-validation.json](artifacts/binary-validation.json).

| Corpus role | Result |
| --- | --- |
| Six stripped O2 release controls | Three affected and three fixed code matches |
| Independent Fedora libbrotlidec 1.2.0 build | Statically reported 1.2.0; potentially affected, backport review needed |
| Node v22.14.0 ARM64 local installation | Statically reported embedded Brotli 1.1.0; potentially affected |
| WOFF2 decoder | Decoder import, not an embedded-code match |
| Encoder library and Python executable | No matching decoder code; remain unclassified, not certified absent |
| Firefox libxul and Qt WebEngine Core (199 MB / 193 MB) | Inspected without size-limit gaps; unmatched code remains unresolved |

The independent package results are version evidence, not exact code matches.
The Node installation's download provenance was not independently authenticated.

The packaged reference catalog now contains 24 generated O2/O3 PIC/non-PIC
references across six reviewed releases. The real-build matrix exercises 24
configurations and 36 links, including stripped binaries, removed section
headers, shifted PIE/non-PIE layout, and archive members. On the matching build
host, every target is checked against the complete packaged corpus, including
the opposite-state references, not merely its own generated signature.

## Why the earlier catalog missed real decoders

A different optimization level changes whole-decoder text. Adding reviewed O3
profiles resolves that demonstrated miss without relaxing matching rules.

LTO is a different failure mode: with the same reviewed source/compiler/hardening
options, a non-LTO shared build matched its object reference, while an LTO build
failed to match its own pre-link fat-object reference. Link-time optimization
changes the code being fingerprinted. More pre-link flags alone cannot solve it.
LTO code therefore needs further build evidence or disassembly review rather
than an invented exact-match classification.

## Model review example

Static inspection of the hashed Node corpus binary's command-switch helper and
its safe command-processing caller found the pre-fix invalid-switch behavior:
the guard returns false and the caller converts that result to the input-needed
status, rather than preserving a format error. This is a bounded model-reviewed
observation of that path, not a scanner-generated code match or an exploitability
claim. No target binary was executed and no malformed compressed input was used.

The triage workflow retains function/range evidence and missing-scope details.
The [triage validation summary](artifacts/binary-triage-validation.json) records
the final Node and Fedora scope selections, fragment identities, and completeness.
The 118 MB Node input produces only 14,440 bytes of code fragments for objdump;
the whole input is never copied. Original SHA-256 is streamed, and input mutation
invalidates collection.
An entry-point-only packet is orientation material, not complete coverage of
block-switch status propagation. A fixed-looking helper or reported fixed version
cannot clear uninspected paths or additional embedded copies.

## Large-file resource policy

There is no default regular-file size or aggregate input-byte cap. FileData
keeps a stable open descriptor and uses bounded pread access; it does not copy
or map the input. Matching scans executable PT_LOAD ranges, generic indicators
scan validated load ranges once, and ELF metadata is read at validated offsets.
The one necessarily complete pass computes the whole-artifact SHA-256 in chunks.

A [6.44 GB sparse ELF validation](artifacts/binary-size-validation.json) found the
expected code and version above the 4 GiB offset with zero gaps and 30,892 KiB
maximum RSS. Sparse-hole timing is not a real-disk throughput benchmark; the
invariants are correct 64-bit offsets, streamed identity hashing, bounded analysis
reads, and no proportional heap allocation or scratch copy.

The regression suite checks sparse code/symbol access beyond 6 GiB by default.
Enable `BROTLI_LARGE_FILE_TESTS=1` for the complete large-file hash/CLI regressions.
Archive members and decompression streams have separate 8 GiB/item and 64 GiB
cumulative expansion budgets; sequential expansion may require temporary spooling
for later random access. Explicit user-selected input caps remain available.
