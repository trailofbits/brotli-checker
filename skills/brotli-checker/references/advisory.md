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
  or renamed binaries can evade these clues. The helper does not disassemble,
  load libraries, invoke interpreters, or execute target tools.
- ZIP-family archives and TAR variants are bounded by file, total-read,
  nesting, and count limits. Unsupported/encrypted content, unreadable files,
  symlinks, large files, and remote build inputs remain coverage gaps. Archive
  member names are report labels; no member is extracted to disk.
- Exit 0 applies only to reported items that match known fixed source or a
  supported upstream version rule. Exit 3 includes no matches. Neither clears
  uninspected copies or establishes application reachability.

## Escalating an unresolved result

For a maintainer investigating exploitation, establish attacker control,
authentication order, the actual decoder/error path, buffering and chunking,
allocator/platform, mitigations, process privileges/sandbox, repeatability, and
demonstrated impact. A reachable decoder or a lab-specific PoC alone does not
settle an application's exploitability. Keep this analysis in the technical
evidence; give non-experts a specific update or a clear request for missing
information.
