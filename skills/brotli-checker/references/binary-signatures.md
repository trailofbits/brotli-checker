# Stable decoder-data recognition

The scanner uses exact data signatures to recognize Brotli decoder tables across
compiler profiles, independently of symbol names and patch-specific code matches.
This is a component-recognition layer, not a new vulnerability verdict.

## Signatures and provenance

- **Full command lookup table:** all 704 eight-byte `CmdLutElement` rows,
  including both 16-bit offsets, in little- and big-endian layouts. A 64-byte
  anchor locates candidates; all 5,632 bytes must match. A matching anchor alone
  is not accepted. The deterministic construction follows
  [v1.2.1 prefix.c](https://github.com/google/brotli/blob/db24a98aed38a16de78cc05ca15cdd8dc2a0d92d/c/dec/prefix.c),
  with independent test digests computed from the literal
  [prefix_inc.h initializer](https://github.com/google/brotli/blob/db24a98aed38a16de78cc05ca15cdd8dc2a0d92d/c/dec/prefix_inc.h).
- **Code-length decoding table set:** all three exact arrays
  `kCodeLengthCodeOrder`, `kCodeLengthPrefixLength`, and
  `kCodeLengthPrefixValue` from
  [decode.c](https://github.com/google/brotli/blob/db24a98aed38a16de78cc05ca15cdd8dc2a0d92d/c/dec/decode.c).
  No individual short table suffices. This recognizes builds that construct
  the command table at runtime rather than storing it in the file.

The complete command table and all three byte arrays are identical in the six
reviewed releases 1.0.9/1.0.10, 1.1.0/1.1.1, and 1.2.0/1.2.1. The serialized
command-table SHA-256 values are:

```text
LE fdbc5d5f207a43d34b26441e29b7024f4f3d00be66502d8a73233bcbe9f6c1b4
BE 68734cc6cd5855efe1e04a05b45b754871f1a3f127510c34bb57b6bacc81afa6
```

The shared Brotli dictionary is deliberately not a decoder signature. Encoders
can contain it; a tested encoder also contained the code-order array alone.
Ports may share these tables too, so they do not establish Google C identity.

## Evidence and interpretation

Both binary scan paths expose `detection_status` independently of `patch_status`:

| Detection status | Evidence |
| --- | --- |
| `decoder_code_identified` | Existing reviewed compiled-code reference matched. |
| `decoder_tables_detected` | Full command table or complete three-table set matched. |
| `decoder_symbols_defined` | ELF decoder API definitions found. |
| `decoder_import_detected` | ELF imports identify an external provider to investigate. |
| `name_or_string_only` | Recognized strings, not established decoder code. |
| `not_detected` | These detectors found no qualifying evidence; not proof of absence. |

Table evidence includes stable signature IDs, byte sizes, file offsets, and ELF
virtual addresses. ELF scanning is restricted to validated file-backed `PT_LOAD`
segments; appended nonloaded data does not count. Invalid/unsupported ELF layouts
produce incomplete recognition. For PE/Mach-O/WebAssembly magic candidates,
matching uses file bytes and explicitly reports
`file_bytes_not_loader_validated`: those formats' sections and runtime use have
not been validated. Data can be embedded as a resource rather than used as code.

Scanning uses bounded overlapping chunks and sparse reads, with no default file
size cap. Overlapping mappings are scanned as a union once; each accepted table
must still fit wholly within at least one original mapping. A candidate-work limit produces an explicit coverage gap and retains
completed evidence. Offsets identify the first observed instance of each table,
not a complete copy count. Tables need not belong to one decoder instance.

Table matches alone remain patch-unresolved and exit 3 in the main scanner.
They neither override affected code evidence nor convert a reported fixed
version into a fixed binary. The report explicitly distinguishes this case from
generic unrecognized binaries and weak string clues.

## Follow-up analysis

1. Preserve the artifact hash, table offsets, mapping scope, and addresses.
2. In a trusted static analysis tool, locate **code references to the tables**.
   The table bytes themselves are data; do not disassemble them as instructions.
3. Identify the decoder and review command processing, invalid block-switch
   handling, and propagation of terminal errors through safe/unsafe paths.
4. Use the bounded disassembly helper on those executable ranges. Record the
   reasoning and any remaining gaps, separately from exact code matches.
5. Establish the deployed provider and input route before claiming runtime use.

This does not automatically recover cross-references, prove patch semantics, or
clear other copies. Packed/encrypted tables, altered layouts, synthesized tables
without the fallback set, and unreviewed implementations can remain undetected.

## Validation scope

On 2026-10-26, recognition matched 600 normal, 600 stripped, and 504 sectionless
retained linked fixtures across 12 ELF machine/class/byte-order identities.
Eight additional GCC 16 LTO/GC normal/stripped builds matched despite missing
packaged code fingerprints; two runtime-initialized-table builds matched using
only the three-table set. Encoder/common/dictionary and version-only controls did
not match. A 3,976-ELF system sample returned three confirmed Brotli consumers;
a separate Node/382-extension sample returned Node alone. Other individually
checked consumers included Firefox, Qt WebEngine, Ghostscript, and libbrotlidec.
Unmatched system files were not an independently labeled absence corpus; these
results are not a universal false-positive/false-negative rate or safety claim.
