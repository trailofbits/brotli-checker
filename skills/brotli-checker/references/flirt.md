# Automatic FLIRT function recognition

FLIRT supplies named code windows between weak component clues and patch-specific
code evidence. It can recognize individual surviving functions when a whole
decoder reference misses. Missing sibling functions, including APIs removed by
linker garbage collection, do not invalidate a recognized function.

## Run it

FLIRT runs automatically for ELF binaries and uses the
pinned `python-flirt==0.10.2` backend on Python 3.12-3.14:

```sh
# From the repository; use python so uv selects the project environment.
uv run --python 3.14 --extra flirt python skills/brotli-checker/scripts/brotli_inventory.py \
  /path/to/application --json

# With a copied/installed skill outside the repository:
uv run --python 3.14 --with python-flirt==0.10.2 \
  /path/to/skill/scripts/brotli_inventory.py /path/to/application --json
```

Both inventory CLIs enable FLIRT by default; `--no-flirt` explicitly disables it.
The backend is loaded once, lazily, so source-only scans do not require it. `--flirt-references PATH` selects a trusted
bundle manifest and also enables FLIRT. The manifest and its adjacent `.pat`
must stay together. No signature download or target execution occurs during
scanning. An unavailable automatic backend produces a coverage gap;
other analysis continues. An invalid explicitly supplied bundle is a CLI error, not an empty result.
An unavailable packaged bundle is a coverage gap.

Python 3.15 remains supported by the core scanner. The pinned FLIRT backend has
no 3.15 wheel and its bundled PyO3 does not build against 3.15; use 3.12-3.14 for
full analysis rather than suppressing the missing-backend gap.

## Recognition contract

This is real [`python-flirt`](https://github.com/williballenthin/lancelot/tree/9de1820bf36872175a08987882dc42f6112d2f44/pyflirt)
matching of a deliberately strict FLIRT `.pat` subset. Each record has:

- a 32-byte masked head, zero CRC region, and one public identifier at offset 0;
- the **entire masked remainder** through its declared size, not just a prefix;
- 32-65,536 bytes, at least half exact bytes, and an exact 16-byte search anchor.

External reference constraints, aliases, nonzero CRC regions, and unsupported
tail syntax are rejected. The upstream backend delegates reference resolution
to its caller; this scanner does not silently accept unchecked references.
Generated patterns mask relocation bytes but do **not** prove the relocated
call/data targets. This is not a general importer for arbitrary IDA signature
databases or a semantic-equivalence engine.

A centered 16-byte window in the longest exact run avoids common prologues.
Overlapping native byte searches read normalized ELF executable `PT_LOAD` unions
in chunks.
Candidates must fit an original executable mapping. All candidate function bytes
are rechecked against the mask and then the real backend. Candidate comparisons,
bytes examined, output, and ambiguous alternatives have explicit bounds; hitting
one preserves partial evidence and produces a gap. There is no default file-size
cap, and the scanner never reads the entire target into memory for FLIRT.

Overlapping anchors are considered. Different matching records at one offset
remain ambiguous. If candidate collection is incomplete, retained matches have
`ambiguity_complete=false` and no definitive name. A recorded byte extent is the
matched signature window, not independently recovered function boundaries or a
control-flow graph.

## Interpret the result

- `decoder_functions_recognized` / `decoder_function_signature` identifies
  function-pattern evidence, with offsets, sizes, candidate names, and compatible
  reference profiles. Use these windows for bounded disassembly.
- `source_state_provenance` describes the source used to generate a reference.
  It is **not** the inspected binary's patch state. The adjacent `source_state`
  explicitly says `provenance_only` in emitted profile evidence.
- FLIRT alone leaves the main scanner at `unknown` / exit 3. Matching a pattern
  from a fixed source build cannot clear another function, decoder copy, or
  unresolved relocation target.
- Existing affected/fixed compiled-code evidence keeps precedence. Table,
  symbol, import, and FLIRT evidence remain available together.

Inspect the block-switch/error-propagation functions and their callers together.
Do not conclude that a function is absent from a nonmatch: inlining, LTO, changed
instruction selection, unsupported compiler profiles, packing, and different
implementations can defeat these patterns. Current mapping support is ELF;
requested FLIRT analysis of other native formats reports an unsupported gap.

## Generate and reproduce references

Use complete, trusted source trees and compilers. The builder checks `decode.c`
against the reviewed C registry, hashes headers and objects, enumerates valid ELF
function symbols, masks supported relocations, and drops underspecified or
same-target name-ambiguous patterns. Patterns are shared across compatible
profiles; profile groups are provenance, not all-functions-match requirements.

```sh
uv run --extra flirt python scripts/build_flirt_references.py \
  /sources/brotli-1.2.0 /sources/brotli-1.2.1 --cc cc \
  --output /output/brotli-flirt.json

uv run --extra flirt python scripts/build_flirt_references.py \
  --merge /profiles/x86.json --merge /profiles/arm.json \
  --output /output/merged.json
```

Defaults cover `-O2`/`-O3`, PIC/non-PIC. Repeat `--cflags='...'` for other reviewed
profiles and retain `--build-note` for portability changes. Use the owning builder
for updates; do not edit generated PAT/bundle files. The shared runtime validator
checks the grammar, bounds, group schema, and PAT SHA-256 before publication.
The bundled patterns are generated from MIT-licensed Brotli, not redistributed
Hex-Rays signatures. See [third-party notices](THIRD_PARTY_NOTICES.md).


## Packaged corpus and observed coverage

The bundled corpus contains 3,439 full-function records across 360 provenance
profiles and 12 ELF machine/class/byte-order identities. It covers the six
reviewed C releases at `-O2`/`-O3`, PIC/non-PIC, with GCC 14 cross-target builds,
AArch64 GCC 16, and both GCC 14 and Clang 19 LoongArch profiles. Header hashes and
build notes record LoongArch portability inputs; no C source-state rule is
transferred to other implementations.

Validation recognized functions in all 1,704 retained linked variants (600
normal, 600 stripped, 504 sectionless), recovering 37 names with consistent
function sets across stripping variants. The stable table detector already
recognized these files; FLIRT adds named code windows rather than claiming
1,704 newly discovered decoder-bearing files. A hardened build outside the exact
code profiles yielded 21 functions; an O2 LTO build yielded nine. Some other
compiler/LTO profiles still remain table-only. Version-only and encoder/common
controls did not match.

A Node probe demonstrated why anchor selection matters: generic prologue
anchors exceeded the work budget. Centering the anchor in the longest exact
run reduced candidate-record checks from 19,785 to 448, recognizing five
functions without raising the limit. Native chunk searches reduced the same
probe from about 61 seconds to about 12 seconds on the test host. These are
sample-specific measurements, not promised runtime or universal detection rates.


A broader 3,976-ELF, 2.99 GB system sample completed without ambiguity or work
limit gaps: only Qt WebEngine yielded function matches (three). Known Brotli
consumers such as the system decoder library and Ghostscript remained
independently table-positive compiler-profile misses. Eleven additional common
system-library controls and 50 version-only/encoder/common controls had no
matches. Unmatched files are not classified Brotli-free. On the measured host,
the broad pass took about six minutes and 86 MiB peak RSS; prefer focused
application/deployment scope when doing interactive follow-up.
