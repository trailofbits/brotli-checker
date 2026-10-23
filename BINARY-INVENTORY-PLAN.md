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

## Independent binary scanner review (2026-10-23)

Outcome: review binary matching and integration, and identify useful real binary
test inputs. User explicitly requested independent agents. This is a focused
direct review, not a formal Vivisect assurance run.
Acceptance: source-grounded findings checked by the primary reviewer; baseline
tests/static checks; real local binary corpus with provenance, hashes, results,
and explicit unknowns. No target execution, production edits, or publication.
Ownership: independent matcher reviewer, integration reviewer, and corpus tester;
primary reviewer verifies evidence and records the consolidated outcome here.
Review artifacts: artifacts/review-20261023/. Existing evaluation/ is untouched.
Review findings verified by primary reviewer:
- Text rendering hides a fixed-code match when an earlier Brotli filename hint
  has the same display priority. Reproduced using the real 1.2.1 stripped binary
  under label libbrotli.so; JSON retains the match and exit remains conservative.
- Normal ELF matching returns before existing decoder-symbol collection. Verified
  on /usr/lib64/libbrotlidec.so.1.2.0: without matching it has a decoder-symbol
  candidate, with matching only a generic binary candidate. This loses triage
  evidence, not a false-safe verdict.
- Reference builder accepts repeated source inputs and emits duplicate IDs that
  its consumer rejects. Independently built the same 1.2.1 tree twice: two
  entries, one unique ID. Low-severity maintainer-path defect.
- Additional integration observations: named files have heterogeneous duplicate
  finding rows, and binary reports omit applied limits. These are output-design
  improvements, not demonstrated incorrect patch classifications.

Verification: 89 standard tests passed (90.70% coverage), all 12 optional
real-build cases passed, Ruff check/format and ty passed. No production edits.
Independent matcher review also regenerated all 12 packaged entries identically.
Primary reviewer checked corpus output and all 11 initial file hashes: six local
stripped controls match expected states; Fedora decoder, Node, libwoff2dec,
encoder-only library, and Python remain unassessed with no read gaps under the
selected limits. Same-source -O3 coverage control is recorded by corpus reviewer.

Design recommendation: preserve one per-artifact evidence owner combining name,
format, symbols, code matches and read status; render by evidence specificity
without downgrading affected evidence. Validate generated reference catalogs
with the consumer's validator. Keep unknown distinct from clean. This review
does not establish independent-package recognition or runtime patch status.

Status: complete. Three independent agents delivered matcher/integration notes
and an 11-target corpus manifest with raw output, provenance, and a rerun command
under artifacts/review-20261023/. Artifacts are local and gitignored. Production
files and existing evaluation artifacts were not modified. No fixes or commits
were made as part of this review.

PR publication completed after user confirmed access:
- Pushed committed implementation c7fc248 on codex/elf-brotli-code-matching.
- Opened https://github.com/trailofbits/brotli-checker/pull/6 against main.
- Left concurrent uncommitted independent-review notes and evaluation/ untouched;
  they were not included in the push.

## Review fixes for PR 6

User authorized fixes and patches into the PR. Preserve unknown/affected exit
semantics and bounded reads. Consolidate name hints into content findings, retain
symbols on ELF misses, use a consistent binary schema for unread named files,
record applied budgets, and reject invalid generated catalogs before output.
Use shared 128 MiB file / 1 GiB total defaults so the tested Node build fits;
larger inputs still require explicit budgets. No target execution or fuzzy match
changes. Verify regression failures first, full tests including local real builds,
lint/types, real corpus, then commit and push to existing PR 6. Existing evaluation/
remains untouched. Status: implementation in progress.

Scope expanded by user: diagnose excessive unknowns, and provide bounded objdump
evidence for skill-driven model inspection of unresolved cases. Root cause probes:
whole-object profiles miss O3 and LTO; the Fedora-like LTO link misses even its
own pre-link reference. Safe immediate changes: O3 references; parse defined vs
imported ELF decoder APIs and exact constant-return BrotliDecoderVersion forms.
Old reported versions warn potentially_vulnerable (never definite affected from
version); reported fixed versions never clear binaries. Preserve source/runtime
uncertainty and mixed-copy caution. Bounded disassembly is a separate opt-in
triage helper, not target execution or an automatic semantic patch verdict.
Ownership: primary implements shared metadata assessment and CLI integration;
matcher reviewer owns pure metadata tests; corpus agent owns O3 generator/defaults,
packaged corpus and real-build matrix; integration agent owns triage helper/tests
and skill/reachability guidance. All production patches go into existing PR 6.

Upstream changed during implementation: PR 6 is already merged; fetched main
670a274 and merged its source/archive/fetch/symlink fixes into the follow-up
branch codex/binary-scanner-followup. A new linked PR is required. Independent
merge review found and verified a repaired empty named-container fallback;
the existing unknown/no-absence guarantees remain. Updated tests for intentional
128 MiB/1 GiB defaults and one content finding instead of duplicate name rows.
No unrelated upstream behavior was intentionally removed.

Recognition evidence: Fedora libbrotlidec statically reports 1.2.0 and the local
Node binary reports embedded Brotli 1.1.0. Both now get actionable version-based
warnings; WOFF2 is identified as importing the decoder. O3 corpus regenerated
through builder: 24 refs, SHA-256 b067216c952a881ebb73877ada2c791c21ad2ce5f39a42027d1a6f589ec9614c.
24 real-build cases / 36 links passed against generated and packaged profiles.
Final verification: 285 tests passed with local reference trees (24 real-build
cases, no skips), 90.54% combined coverage. Ruff format/check, ty, and diff checks
passed. Independent re-review approved metadata parsing, merged upstream
behavior, and triage hash binding/range/output/completeness invariants.
Real triage: Node selected 9 relevant functions; Fedora public fallback remains
explicitly incomplete. All objdump invocations read a private snapshot matching
the reported input hash; no targets executed. Validation summaries are under
docs/artifacts/ and docs/binary-validation.md.

Published follow-up: https://github.com/trailofbits/brotli-checker/pull/7 on
codex/binary-scanner-followup, against current main. All requested implementation,
tests, skill workflow, and validation summaries are committed and pushed. Existing
evaluation/ remains untracked and untouched. Local verification is complete;
GitHub CI passed on implementation commit 1b61f7e: Python 3.12, 3.13, 3.14,
3.15, and the existing benign built-in Node fetch check.
