# Binary inventory task

Outcome: read-only local Brotli artifact inventory for patch/quarantine review.
Acceptance: standalone binaries and nested supported bundles; evidence and hashes;
optional exact artifact catalog; bounded reads; gaps explicit; no automatic moves,
execution, library loading, or vulnerability verdict from binary indicators.
Non-goal: CFG/vulnerable-function matching or stripped-code identification.

Design: a separate binary inventory CLI subclasses Inventory only to reuse bounded
filesystem/archive traversal. Its inspect method owns generic binary indicators and
whole-artifact identity; it does not invoke source vulnerability detection. Catalog
labels are user-supplied, not independently validated patch assertions.

Verification: synthetic native formats, nested bundles, catalog match/mismatch,
malformed catalog, missing roots, budgets, and unchanged existing suite; Ruff/ty.
Existing untracked evaluation/ artifacts are unrelated and will not be edited.

Progress: inspected existing traversal, source classifier, CLI, and tests. Implementation
and verification pending.

Completed: binary CLI, exact SHA-256 catalog validation, JSON evidence and gaps,
documentation, and 15 new tests. Shared inspect_container owns archive dispatch;
source classification remains unchanged. Reviewed diff for duplicate traversal and
classification leakage. No user evaluation artifacts modified.

Verification: 33 tests passed on Python 3.12.13; combined line/branch coverage
85.74%, binary CLI 100%. Ruff format/check and ty passed on maintained scripts and
tests; git diff --check passed; subprocess CLI --help smoke passed. Tests include
nested bundles, budgets, missing files, symlinks, malformed catalogs, and unchanged
input bytes. Used installed .venv tools because uv cache writes are unavailable in
the sandbox. No system-wide scan performed. No claim of stripped-code completeness,
vulnerability identification, or verified catalog provenance. CFG matching remains
outside the implemented scope.

## Static decoder code matching (2026-10-23)

New outcome: identify embedded patched/unpatched decoder code in binaries, not
just versions, strings, or whole-artifact identity. ELF64 little-endian is the
initial implementation scope; PE/Mach-O and unmatched code remain unknown.
Design: compile reviewed decode.c references; retain complete executable section
bytes with only ELF relocation fields masked. Match these inside executable
PT_LOAD ranges, independent of target symbols and section headers. No target
execution. Require all reference code sections; report each matched reference
and offset, not an assertion that the entire application is patched. Preserve
mixed states and explicit unknowns. Compiler/LTO/relaxation differences may cause
false negatives; no fuzzy similarity or version inference. References own their
provenance, source hash, object hash, architecture, build flags, and state.
Acceptance: real linked/stripped before/after builds, shifted layout, negative
non-executable data/imports, mixed copies, malformed ELF/reference inputs,
archive integration; existing source scanner unchanged; lint/types/full tests.
Existing dirty edits and evaluation artifacts remain untouched except requested
binary CLI integration and documentation. Reference generation is tool-owned.

Current implementation and review:
- User confirmed ELF/Linux first and requested a PR in trailofbits/brotli-checker.
- Matching is now part of the normal scanner, not only the binary inventory CLI.
  CodeAssessment owns match state/limits; both CLIs share the matcher. Affected or
  mixed code -> normal scan exit 1; fixed-code-only remains review-required (3).
- Generated 12 references: three release pairs, AArch64 GCC 16.2.1 -O2, PIC and
  non-PIC. x86-64 matching/relocations are supported with supplied references;
  no packaged x86-64 corpus or compiler-independent matching is claimed.
- Matching checks complete decoder executable text, excluding relocation fields.
  It does not validate relocation destinations or referenced data. Reference
  metadata records reviewed decode.c identity; compiler/headers are trusted.
- Real-build tests initially rejected non-PIC objects in PIE (linker's read-only
  dynamic-relocation error). Corrected the test/build assumption: non-PIC uses
  non-PIE; PIC tests both links. All 12 real-build configurations then passed.
- Added bounded candidate/match counts, structured coverage limits, malformed ELF
  and catalog checks, archive integration, mixed-copy and negative-evidence tests.
- Full verification and PR publication pending final run/review. Evaluation data
  and downloaded source/build artifacts are excluded from the proposed commit.

Final local verification:
- Full run with local release trees: 100 passed, 90.80% combined coverage;
  includes 12 real-build profiles and both supported PIC link modes.
- Final review preserved ELF-prefixed ZIP traversal; added a regression. Latest
  offline run: 89 passed, 12 optional real-build cases skipped (already passed).
- Ruff format/check, ty, and git diff --check passed. Main CLI also classified
  six actual stripped artifacts correctly: affected exit 1, fixed-code exit 3.
- Source/version behavior remains covered by the existing suite. Matching never
  executes binaries. No claim of whole-application patch proof or completeness.
- PR base verified: origin/main 2771340aa5c0a99c0556fb7645c90dfe5d2ed74e.

PR publication blocked by repository permissions:
- Branch: codex/elf-brotli-code-matching; implementation committed locally.
- Direct SSH push rejected: "Write access to repository not granted."
- GitHub API identity tob-joe has pull=true, push=false on upstream.
- Fork creation rejected HTTP 403: "forking is disabled"; existing personal fork
  lookup returned 404. No remote changes or PR were created.
- Prepared PR body: artifacts/pr-body.txt. Publish after upstream write access or
  an allowed fork becomes available. No unrelated evaluation artifacts committed.
