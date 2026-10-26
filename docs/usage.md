# Scanner guide

Run these commands from the repository root with Python 3.12–3.15. The inventory
scanners use only the standard library; source discovery uses Trailmark through
uv. Keep the skill's scripts and reference catalogs together when copying them
elsewhere.

## Scan files and supplied versions

Pass one or more files, directories, app packages, or unpacked container
filesystems. With no paths or version flags, the scanner checks the current
directory.

```sh
python3 skills/brotli-checker/scripts/brotli_inventory.py /path/to/source /path/to/app --json
```

Without `--json`, output is a plain-language result with next steps. JSON includes
per-copy patch evidence, build/shipment/reachability status, coverage gaps, and a
`user_summary`. Text output escapes paths and control characters; JSON preserves
the original labels as escaped strings. A `!` separates an archive member from
its container; that label is not a filesystem path.

To assess an upstream version obtained separately:

```sh
python3 skills/brotli-checker/scripts/brotli_inventory.py --node-version 24.22.0
python3 skills/brotli-checker/scripts/brotli_inventory.py --brotli-version 1.1.1 --json
```

Both flags can be repeated. They do not discover installed versions or associate
a version with a copy found in the scan. Supply the embedded Brotli version,
not a wrapper package's version. Vendor backports can fix an older release;
ambiguous versions remain unknown. End-of-life Node branches receive upgrade
advice while their decoder patch status remains unresolved. Rules come from the
dated [advisory snapshot](../skills/brotli-checker/references/advisory.md).

### Main scanner exit codes

| Exit | Meaning |
| --- | --- |
| 0 | Reported items meet a known source or upstream-version fix rule, with no recognized scan gaps. |
| 1 | Affected source/code or potentially affected source/version evidence was found. |
| 2 | Invalid arguments or code-reference catalog. |
| 3 | Review is needed: no matches, unresolved candidates, fixed-code-only evidence, or scan gaps. |

Affected evidence takes precedence over gaps: exit 1 can include incomplete
coverage. Inspect the JSON in every case. Fixed evidence for one copy cannot
clear another, and exit 0 does not establish that the running app is fixed.

## Detection and traversal

The scanner compares decoder files with reviewed source fingerprints, checks
modified C decoder patterns, and collects dependency names and binary indicators.
It also records fetch/Undici references in JavaScript and TypeScript, including
source locations. Those references are heuristic leads: browser bindings, custom
functions, and unused dependencies can match. Computed or bundled calls can be
missed. See the [Node/fetch guide](../skills/brotli-checker/references/reachability.md#nodes-built-in-fetch)
to investigate the actual runtime and input path.

Hidden folders, dependencies, and build outputs are included; `.git` is excluded.
Symlinks are skipped. A filesystem alias adds no gap when its resolved target was
checked directly among the supplied roots; unchecked targets and archive links
remain gaps.

ZIP-family archives (including JAR, WAR, and wheel), TAR, gzip, bzip2, and XZ are
recognized by content signatures and filename hints. Renamed archives and
extensionless container layers are supported. Members are inspected without
extracting their paths onto the filesystem. Sequential expansion may spool data
to temporary storage for random access; set `TMPDIR` to a disk-backed directory
for large inputs.

Recognized unsupported formats, including Debian/AR, RPM, Zstandard, 7z, RAR,
SquashFS/Snap/AppImage, and ASAR, produce gaps; supply unpacked files. An
ELF-prefixed AppImage keeps its outer ELF evidence and also reports the opaque
payload gap. The scanner does not extract these formats. Unrecognized encodings
can be missed. Container traversal does not apply whiteouts or reconstruct the
final image.

Dockerfile/Containerfile names, dotted variants such as `Dockerfile.production`,
and `.bzl` files use the existing dependency-declaration analysis. Their matches
are leads only: they do not establish that a package was selected, built, shipped,
or loaded at runtime.

### Resource limits

| Option | Main scanner default |
| --- | --- |
| `--max-file-bytes` | No regular-file/input-member byte cap |
| `--max-total-bytes` | No cumulative input-byte cap |
| `--max-files` | 50,000 files, symlinks, and archive members |
| `--archive-depth` | Two nested containers; accepts 0–5 |
| `--max-expanded-bytes` | 8 GiB per member or expanded stream |
| `--max-total-expanded-bytes` | 64 GiB cumulative expansion |
| `--max-text-bytes` | 128 MiB per source/manifest text analysis |

Use byte counts for byte-limit flags. Total-input accounting includes containers,
expansion, and members, rather than internal read calls. A text-analysis limit
records a gap without suppressing binary inspection. Larger limits increase
resource use; scanning smaller relevant roots can be easier to review.

JSON records applied limits and total, retained, and omitted gap-detail counts.
At most 200 gap details are retained; omitted paths cannot be recovered by
switching output formats. `archives_attempted` counts inspection attempts;
`archives_opened` counts successful opens, even if later member reads fail.

## Discover source callers with Trailmark

After inventory identifies relevant source, collect a call neighborhood for
decoder and fetch APIs:

```sh
uv run --script skills/brotli-checker/scripts/brotli_source_discovery.py \
  /path/to/source > discovery.json
```

The script pins Trailmark 0.7.0. First use may download its dependencies and
parser grammars. It parses source without importing or executing the target.
Choose a relevant source subtree: limits bound caller traversal and output,
not initial parsing. Keep output outside the inspected tree.

JSON includes candidate callsites, caller nodes and edges, entrypoint tags,
resolution/confidence, parser diagnostics, and truncation. Follow these locations
in source to review bindings, input ownership, and build selection. This report
does not change the inventory's patch verdict or establish runtime reachability.
Repository-configured links and entrypoints are declarations to verify.

For a source-reviewed alias or wrapper, add `--symbol download` (repeatable).
This searches its exact name without claiming it resolves to fetch or Brotli.
Use `--language c` or `--language javascript,typescript` to narrow parsing.
Defaults retain up to 32 candidates, 128 caller nodes, 256 call edges, six caller
levels, and 100 parser diagnostics; see `--help` to adjust these limits.

Exit 0 means collection completed, 3 means incomplete evidence, and 2 means
invalid arguments. Neither a successful exit nor an empty neighborhood establishes
that a decoder is fixed or unreachable. Trailmark excludes dependency, build,
and hidden directories and can omit top-level JavaScript calls; keep the broader
inventory and manual review. See the
[source review workflow](../skills/brotli-checker/references/reachability.md#trailmark-source-discovery)
for known gaps and how to interpret graph evidence.

Unavailable grammars and language-provider failures produce an incomplete JSON
report with a `discovery_error` gap. Resolve that setup/download failure before
interpreting the call neighborhood; missing parser evidence is not a negative result.

## Compiled decoder evidence

The main scanner includes code matching for ELF32 and ELF64 executables and
shared libraries in supported byte orders. It compares compiled decoder text
with reviewed references, masking supported relocation fields and documented
linker instruction rewrites. Complete references require every executable object
section, including split hot/cold sections and compiler thunks. Scope-aware
references for `-ffunction-sections` instead require every emitted section for
the literal, command, and distance block-switch paths, their safe variants, and
normal/safe command processing. Any separately emitted related helper, clone, or
cold section recognized by those role patterns or by
`DecodeBlockTypeAndLength` is required too; unrelated public decoder APIs are
not.

Scope-aware matches report `code_scope=patch_bearing_sections_v1`, the mapped
`patch_functions` and positional `section_functions`, and method
`relocation_masked_patch_sections`. Reference generation rejects a missing,
malformed, or over-budget required role. All retained fragments from one
reference must match before its affected/fixed state is reported. Sections can
move independently; their association with one decoder copy and their relocation
targets are not verified. Matching uses executable load segments, so stripping
symbols or removing section headers from the linked artifact does not prevent a
match. Evidence includes source/object hashes, compiler flags, reference state,
scope, and file offsets.

The packaged catalog contains 432 references for Brotli 1.0.9/1.0.10,
1.1.0/1.1.1, and 1.2.0/1.2.1. It preserves all 336 prior references unchanged,
adds 24 complete LoongArch GCC references, and adds 72 scope-aware
`-ffunction-sections -fdata-sections` references for linker-GC builds. The final
population is 360 complete and 72 scope-aware references. Each toolchain set
covers `-O2` and `-O3` with PIC and non-PIC profiles:

| Architecture | Toolchain / additional options |
| --- | --- |
| x86-64 | GCC 14.2.0, including scope-aware linker-GC profiles |
| x86 | GCC 14.2.0 |
| AArch64 | GCC 14.2.0 and GCC 16.2.1, including scope-aware linker-GC profiles for both |
| ARMv7 ARM and Thumb | GCC 14.2.0, `-marm` / `-mthumb` |
| RISC-V64 | GCC 14.2.0, `-mno-relax` |
| PowerPC64 little-endian | GCC 14.2.0 |
| s390x (big-endian) | GCC 14.2.0 |
| MIPS32/64, little- and big-endian | GCC 14.2.0, `-EB` for big-endian |
| LoongArch64 | GCC 14.2.0 and Clang 19.1.7, `-mno-relax`; portability details below |

LoongArch references apply the `BROTLI_MODEL` header guard from upstream
[e230f47](https://github.com/google/brotli/commit/e230f474b87134e8c6c85b630084c612057f253e)
for 1.2.0/1.2.1. The GCC profile uses the Debian LoongArch sysroot; the Clang
profile uses AArch64 LP64 glibc headers for C declarations. Decoder source is
unchanged; `build_note` and `headers_sha256` record the compiler, sysroot,
portability input, and `-mno-relax`. These profiles do not establish coverage
for other LoongArch toolchains/sysroots.

The scope-aware profiles were checked with valid one-shot and streaming decoder
fixtures across all six releases and four optimization/PIC profiles: 24 AArch64
GCC 14, 24 x86-64 GCC 14, and 24 AArch64 GCC 16 cases. Each case checks
normal, stripped, and section-header-free artifacts, paired affected/fixed
references, and a version-only link where garbage collection removes every
required patch role. The 24 LoongArch GCC 14 complete-reference cases received
the same normal runtime/artifact checks without the linker-GC option. These are
profile-specific acceptance results, not compiler-independent coverage.

Linker CPU erratum fixes and inserted veneers can also leave these compiler
profiles unmatched, depending on code placement (including Cortex-A8/A53 fixes).
Custom x86 builds using older non-relaxable GOT relocation types can miss linker
rewrites too. Unmatched code remains unknown; compiler identity alone does not
guarantee a match.

ELF class and byte order are part of reference identity. RISC-V32 and big-endian
PowerPC64 parsing is supported, but they need additional trusted references.
A target absent from the selected catalog produces an explicit coverage gap.
The gzip catalog is bounded to 64 MiB after decompression; plain JSON catalogs
remain accepted.
Both inventory commands accept `--code-references compiled-references.json` to
replace the packaged catalog. See [reference generation](../CONTRIBUTING.md#compiled-references).

| Binary patch status | Interpretation |
| --- | --- |
| `vulnerable_code_match` | Affected reference decoder text matched. |
| `fixed_code_match` | Fixed reference text matched; other copies remain unresolved. |
| `mixed_code_matches` | Both affected and fixed reference text matched. |
| `potentially_vulnerable` | A statically read version precedes its branch fix; verify vendor patches. |
| `not_assessed` | No patch classification; the main scanner uses `unknown`. |

Matching establishes code identity within the checked scope. Different compilers,
flags, LTO, unrepresented split-section layouts, linker relaxation, or alternate
backports can remain unmatched. LTO is not covered by the scope-aware references.
Relocation targets, referenced data, and association of independently matched
sections with one linked decoder copy are not verified. A code match does not
establish runtime linkage, reachability, or that every copy is fixed. A
fixed-only match remains review-required.

On unmatched ELF inputs, metadata distinguishes defined decoder APIs from imports
and reads supported constant-return `BrotliDecoderVersion` functions without
executing them. Old versions support an update warning; a fixed version never
clears a binary. Missing symbols or unsupported instruction forms leave the
version unresolved. PE, Mach-O, and relocatable objects are not classified by the
code matcher.

### Binary rollout inventory

For artifact hashes and rollout tracking, use the separate JSON-only command:

```sh
python3 skills/brotli-checker/scripts/brotli_binary_inventory.py \
  /path/to/installations /path/to/unpacked-image > binary-inventory.json
```

Keep output outside the scanned roots. This command reports recognized native
formats even without Brotli indicators and reuses archive traversal and gap
reporting. Format headers and strings are leads; they can represent imports or
incidental text. Static libraries are inventoried as whole files, without
parsing their objects.

For exact whole-artifact identity, add `--catalog known-artifacts.json`. The
catalog maps lowercase SHA-256 digests to nonempty labels:

```json
{
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "example service build, pending rebuild"
}
```

Replace the example digest with a hash from a trusted release artifact or build
record. Labels are supplied by the catalog and are not verified. Identity
matching covers complete files or archive members, including files without
recognizable Brotli strings; it does not identify a library embedded in a larger
executable or a rebuilt artifact.

Binary JSON schema 2 records candidate evidence, content hashes for fully read
candidates, optional catalog labels, and gaps. Unreadable or limited named
candidates can have null hashes. Large regular files use sparse offset reads for
ELF analysis and a streamed full-file pass for SHA-256, without copying or mapping
the whole file. Detected input mutation makes the result incomplete.

This command defaults to 100,000 files/members and two archive levels, with the
same input/expansion byte limits as the main scanner. Its exits differ:

| Exit | Meaning |
| --- | --- |
| 0 | No candidates and no reported gaps. |
| 1 | Inventory candidates, including fixed matches. |
| 2 | Invalid arguments or catalog. |
| 3 | Coverage gaps, even when candidates were found. |

It does not move or quarantine files. Before acting on inventory, resolve package
ownership and dependencies and recheck the containing artifact's hash.

### Review unresolved compiled code

To collect bounded disassembly for a relevant unresolved ELF, use a trusted host
`objdump`:

```sh
python3 skills/brotli-checker/scripts/brotli_binary_triage.py /path/to/application > triage.json
```

The helper selects block-switch/command-processing symbols, falling back to
decoder entry points. For stripped code, explicit address or file-offset ranges
require trusted map/link or scanner evidence; see `--help`. It hashes the input
and records commands, selected ranges, fragment identities, truncation, and gaps.
Only bounded code fragments are copied for disassembly. The target is never
loaded or executed. The host `objdump` must support the target architecture.
ARM Thumb symbols select Thumb decoding automatically; for a trusted explicit
Thumb range add `--thumb`. An architecture/tool mismatch leaves collection incomplete.
MIPS raw disassembly currently accepts classic MIPS32r2/MIPS64r2 selected from
ELF ISA flags, including ELF32 N32 with MIPS64r2. MIPS16, microMIPS, other ISA
revisions, vendor-machine/ASE flags, and incompatible symbol-declared modes
remain explicitly incomplete; they are not decoded using a guessed r2 mode.

Exit 0 means evidence collection completed; exit 3 means it is incomplete.
Neither is a patch verdict. Review affected and fixed control flow, including
invalid-switch handling and status propagation through callers. Keep model
interpretation separate from exact code matches and preserve unknown status
when relevant paths are missing. Follow the
[binary review workflow](../skills/brotli-checker/references/reachability.md#bounded-binary-patch-triage).
