# Advisory and detection evidence

Snapshot verified **2026-10-23**. Refresh vendor guidance when assessing a live
deployment; the scanner is offline and does not update its rules automatically.

## Primary sources

- [Google Brotli fix, 0ed4268a4401abcb4472096340477cf4af7d1a2b](https://github.com/google/brotli/commit/0ed4268a4401abcb4472096340477cf4af7d1a2b).
- [Brotli 1.0.10](https://github.com/google/brotli/releases/tag/v1.0.10),
  [1.1.1](https://github.com/google/brotli/releases/tag/v1.1.1), and
  [1.2.1](https://github.com/google/brotli/releases/tag/v1.2.1) security releases.
- [CNA record](https://www.cve.org/CVERecord?id=CVE-2026-111497), also available as
  [machine-readable CVE JSON](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/111xxx/CVE-2026-111497.json).
- [Node.js October 21 security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

The decoder conflated an invalid block switch with insufficient input. The fix
returns a format error and propagates status through the block-switch wrappers
and command processing. Node's advisory describes repeated input buffering into
an eight-byte internal buffer, causing memory corruption with possible crash,
disclosure, or execution.

| Component/branch | Published affected versions / scope | First fixed release |
| --- | --- | --- |
| Brotli 1.0 | 1.0.3 through 1.0.9 | 1.0.10 |
| Brotli 1.1 | 1.1.0 | 1.1.1 |
| Brotli 1.2 | 1.2.0 | 1.2.1 |
| Node.js 22 | Advisory covers 22.x before the security release | 22.23.4 |
| Node.js 24 | Advisory covers 24.x before the security release | 24.22.1 |
| Node.js 26 | Advisory covers 26.x before the security release | 26.12.1 |

The CNA record has disjoint Brotli version ranges. A single comparison against
1.2.1 would incorrectly warn on fixed 1.0.10 and 1.1.1. Other Node branches,
forks, prereleases, and custom builds need decoder-specific evidence. The helper
does not assert that every historical Node release contains an affected decoder.
The [Node.js release schedule](https://github.com/nodejs/Release/blob/main/schedule.json)
marks Node 20 and the historical odd-numbered branches through 25 as end of life
on this snapshot date. The helper recommends a supported fixed branch for these
versions while retaining unknown decoder patch status and exit 3. Future branches
outside the snapshot are not assumed to be end of life.

An older version can contain a vendor backport. Establish the OS release,
provider, architecture, and complete package revision, then use that provider's
advisory and native package version ordering. Do not compare distro revisions as
upstream SemVer or transfer one provider's fixed revision to another. Verify the
file/package actually loaded by the serving process and whether it restarted.
An updated host package does not establish the state of a container, native
extension, or statically linked executable.

## Fingerprint provenance

[fingerprints.json](fingerprints.json) contains 20 distinct decoder-file SHA-256
fingerprints: 17 vulnerable and three fixed. For upstream 1.0.3–1.0.10,
1.1.0–1.1.1, and 1.2.0–1.2.1, release files were downloaded and hashed. Several
releases share identical files. The remaining vulnerable variants came from
immutable repository revisions in the community inventory linked below. Their bytes were
downloaded, their Git blob hashes verified, and their old block-switch handling
compared with the upstream fix. Each entry includes its retrieval URL and hash.
An exact fixed match concerns only that decoder file, not an entire backport,
header set, selected build, or running application.

The [community inventory](https://gist.github.com/N3mes1s/ed33893da270decbb0b4128807fb2141)
at revision `6f34a3ae446cbba851214fd6a0b40d3a6e3c786f` is a positive set of source
containment findings. Its default-branch matches and verified pinned dependency
chains are discovery leads. They do not prove compilation, shipment, input
reachability, or exploitation, and omission from the inventory is not evidence
of absence. Do not use a changing repository count as a deployment count.

## Detection limits

- Exact hashes work independently of filenames but change with whitespace,
  line endings, or patches. Modified C-like source uses conservative pattern
  checks; an old invalid-switch guard plus old call sites is a warning, while
  unfamiliar or fixed-looking source remains unknown until reviewed.
- The pattern checks are not a C parser or preprocessor. Conditional code,
  partial backports, macros, amalgamations, and alternate fixes need review.
- Library names, decoder strings, imports/exports, and manifest dependencies
  establish candidates, not vulnerable implementation identity. Static, stripped,
  or renamed binaries can evade these clues. Compiled ELF decoder references can
  identify matching executable code without symbols, but only within the
  documented architecture/compiler corpus. Relocation targets/data and other
  copies remain unverified. On unmatched ELF builds, defined/imported decoder
  symbols and statically decoded constant-return version functions provide
  additional triage evidence. An old reported version warrants update/backport
  review, never a definitive vulnerable-code claim; a fixed reported version
  never clears a binary. The inventory does not load libraries or execute target
  tools. The separate opt-in triage helper invokes trusted host objdump to collect
  bounded disassembly for model inspection; it never executes target code.
- JavaScript/TypeScript fetch references and Undici imports/dependencies identify
  possible Node HTTP response-decoding routes even without a Brotli dependency.
  They do not establish the fetch binding, runtime, patch state, or input owner.
  The bounded heuristic skips comments/ordinary strings and preserves templates;
  literal template text can produce extra leads. Computed names, dynamic loading,
  bundler rewrites, and unavailable source can hide calls. See the
  [Node/fetch guide](reachability.md#nodes-built-in-fetch).
- ZIP-family archives, TAR, gzip, bzip2, and XZ are identified by known content
  signatures as well as filename hints, including extensionless container layers.
  Expansion, member reads, nesting, and file counts are bounded. Recognized
  unsupported formats (including AR/Debian, RPM, Zstandard, 7z, and RAR), encrypted
  content, unreadable files, unchecked symlink targets, and limits produce gaps.
  Signature-free or unrecognized encodings can be missed. No member is extracted;
  hostile names and error messages are escaped in text and JSON output. Container
  traversal inventories layers without reconstructing a final image filesystem.
- Filesystem symlinks are never opened. When a resolved target was visited
  directly among the supplied scan roots, the alias adds no gap.
  Broken/external/unchecked targets and archive links remain gaps. Python bytecode
  symbol strings are not native-decoder evidence; Python project metadata is
  checked in dependency fields rather than its project description.
- Exit 0 applies only to reported items that match known fixed source or a
  supported upstream version rule. Exit 3 includes no matches. Neither clears
  uninspected copies or establishes application reachability.

Validation covers source references, synthetic ELF/packaging fixtures, an opt-in
suite for locally compiled ELF artifacts, and a benign loopback test of built-in
Node fetch's Brotli response decoding. No deployed application or production
binary's patch state was validated; no malformed or exploit payload was executed.
The fetch test establishes a decoding route, not CVE triggerability.
See the repository's [validation record](https://github.com/trailofbits/brotli-checker/blob/main/docs/validation.md).

## Escalating an unresolved result

For a maintainer investigating exploitation, establish attacker control,
authentication order, the actual decoder/error path, buffering and chunking,
allocator/platform, mitigations, process privileges/sandbox, repeatability, and
demonstrated impact. A reachable decoder or a lab-specific PoC alone does not
settle an application's exploitability. Keep this analysis in the technical
evidence; give non-experts a specific update or a clear request for missing
information.
