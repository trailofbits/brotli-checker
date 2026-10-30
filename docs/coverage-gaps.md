# Setups beyond the architecture matrix

The QEMU matrix varies architecture, optimization, PIC/PIE and stripping. It does
not establish coverage for every way a decoder is built, linked, or delivered.
These setups were independently investigated with benign fixtures.

| Setup | Reproduced gap | Current handling |
| --- | --- | --- |
| `-ffunction-sections` with `--gc-sections` | A real decoder object had 37 executable sections, exceeding the 16-section reference limit. Increasing the limit alone still missed the linked decoder because GC removed nine unrelated public APIs. | Implemented scope-aware references require the complete patch-bearing role population while excluding unrelated APIs. Packaged coverage is limited to the listed x86-64/AArch64 GCC profiles. |
| Different compiler on the same ISA | LoongArch GCC 14 binaries ran correctly but did not match the earlier Clang 19 corpus. | Added a separately generated and runtime-validated GCC 14 profile. Other compilers, versions, flags, and sysroots remain unknown without their own references. |
| Non-C/C++ imports and FFI | Source-only wrappers and runtime APIs could produce no findings; several ecosystem manifests were not dispatched. | Collect bounded language-scoped import/API/linkage leads and selected dependency fields. Resolve actual native providers versus independent ports; generated/computed imports and arbitrary aliases remain limitations. |
| Partial function matches / changed profiles | Whole-decoder identity can miss while individual function bodies survive. | Optional FLIRT recognizes complete masked function windows independently; missing sibling functions are allowed. Compiler changes, inlining, LTO, unsupported mappings, and budget exhaustion remain explicit limits; no patch verdict follows from a function name. |
| LTO | The linked decoder can differ from its own pre-link fat-object reference. | Stable decoder tables identify decoder data in tested LTO builds. Native hosted-runner controls retain exact post-link hashes, while function-pattern state remains provenance until one copy is independently bound. |
| Dynamically linked application | A consumer importing Brotli remains unresolved when scanned alone. Scanning the bundle finds the sibling affected DSO, without associating it to the importer or proving loader selection. | Scan the supplying libraries and verify deployment linkage. No `ldd`, host-loader guessing, or runtime-selection claim. |
| SquashFS/Snap/AppImage/ASAR | Opaque bundles could produce no findings and no coverage gaps. | SquashFS magic and the named formats now produce explicit unsupported-payload gaps. An ELF-prefixed AppImage keeps outer ELF evidence; no payload is extracted or counted as inspected. |
| Dockerfile/Containerfile and `.bzl` | Dependency declarations were not routed to the existing manifest analysis. | Exact and dotted container-file names plus `.bzl` now use dependency-lead collection, without claiming selection, build, shipment, or runtime use. |
| ar/DEB, RPM, zstd packages | Package containers previously stopped at an unsupported gap. | Bounded in-memory traversal now covers regular ar/DEB, RPM/cpio, and zstd while preserving package ownership and expansion limits. Thin ar and unrecognized payloads remain gaps. |
| OCI layered filesystems | Gzip layer traversal did not apply whiteouts. | Final image views now apply whiteouts and opaque directories; historical events remain separate and are never called shipped. |
| PE/Mach-O | ELF function profiles could not be scoped safely to native loaders. | Explicit native FLIRT profiles are format/ABI-bound and scan validated PE sections or Mach-O slices. A native build pipeline generates relocation-masked patch-role candidates and paired opposite-state controls; it does not transfer ELF profiles or infer a verdict from scattered matches. |

## Garbage-collected code acceptance

A fixed classification does not come from making absent reference sections
optional. For split code, the builder requires the emitted sections implementing
all three block-switch classes, their safe variants, and command
processing/status propagation. It also requires related emitted helper and
cold/clone sections recognized by the role patterns and
`DecodeBlockTypeAndLength` helper pattern. ELF function symbols must identify
nonempty, in-range `SHT_PROGBITS` sections with allocated/executable flags. If
those roles cannot be mapped within the section budget, reference generation
rejects the layout.

The packaged catalog has 72 scope-aware references: all six releases at
`-O2`/`-O3`, PIC/non-PIC, for x86-64 GCC 14, AArch64 GCC 14, and AArch64 GCC 16.
All 24 cases in each toolchain set passed valid one-shot/streaming runtime checks,
normal/stripped/section-header-free matching, paired affected/fixed controls, and
a version-only missing-role control. The catalog also adds 24 complete
LoongArch GCC 14 references validated by the normal 24-case matrix.

The required evidence remains relocation-masked code identity, not a proof of
relocation destinations, data identity, association of separately matched
sections with one decoder copy, runtime selection, or every embedded copy.
Identical-code folding may reuse an offset. Fixed-code-only evidence remains
review-required. LTO and unrepresented compiler/profile/layout combinations
remain unknown. Both affected and fixed source controls must work after GC,
stripping and section-header removal, while a missing patch-bearing section or
opposite-state code must not satisfy the reference.
