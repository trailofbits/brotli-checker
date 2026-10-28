# Structured defensive analysis

The inventory produces an artifact registry and qualified relations in addition
to per-copy findings. None of the relations transfers a fixed verdict between
artifacts. All input is local and explicitly supplied; no target or loader is run,
no host package database is consulted, and no symbol server is contacted.

## Scope and providers

Use `--deployment-root /supplied/image-root` for an extracted filesystem whose
absolute loader paths and package metadata belong together. Ordinary roots do
not acquire the host's `/lib` or `/usr/lib`. Archive namespaces are separate.
ELF `DT_NEEDED`, SONAME, RUNPATH and RPATH declarations produce compatible
in-scope candidates after traversal. `$ORIGIN` is interpreted as data within that
namespace, never passed to a shell. Unique, ambiguous, missing and incompatible
candidates remain distinct; a unique candidate does not prove loader selection.
Unsupported tokens and escaping paths remain unresolved.

## Function graph and debug data

Recognized ELF code/data seeds, symbol bounds, unwind starts, relocations and
bounded instruction decoding feed `analysis.function_graph` on each artifact.
AArch64 has a built-in decoder for supported reference/branch forms; x86-64 uses
pinned Capstone. Direct edges are local evidence, not reachability or fix proofs.
Unknown indirect calls, unsupported relocations/ISAs and exhausted budgets are
gaps. `--no-xrefs` explicitly skips decoding and is recorded in configuration.
Use graph function windows and FLIRT windows for bounded triage/model inspection.

Repeat `--debug-file /trusted/companion` to supply debug artifacts. ELF build IDs
or debuglink CRC, Mach-O UUID, and PE/PDB GUID-age must agree before enrichment.
Verified ELF DWARF lines use pinned pyelftools; embedded source paths are not
opened. Duplicate/mismatched identities and unavailable symbol streams remain
unresolved. PDB identity and PE exception bounds do not imply full PDB symbol
support. Names or line mappings alone never establish patched code.

## SBOM and package provenance

`--sbom /local/document.json` parses CycloneDX or SPDX even with a nonstandard
filename. Recognized `bom.json`, `sbom.json`, `.cdx.json` and `.spdx.json` files
are also parsed during traversal. Components, dependency relationships and
completeness declarations are retained. Only an exact scanned SHA-256 creates
an `artifact_hash_bound` relation; declared signatures are not verified
attestations. An incomplete BOM cannot establish component absence.

Same-root dpkg status/list/md5sums and apk installed records produce ownership
relations. RPM headers bind payload paths and declared hashes to the same
archive. Legacy MD5/SHA-1 matches remain weaker than SHA-256 binding. Modified,
ambiguous and unowned files stay distinct. Package ownership does not clear
statically embedded or vendored copies.

`--vendor-snapshot /local/snapshot.json` accepts a dated local assertion set:

```json
{
  "schema_version": 1,
  "snapshot_date": "2026-10-28",
  "vendor": "debian",
  "release": "13",
  "assertions": [{
    "package": "libbrotli1",
    "fixed_version": "1.2.0-2+deb13u1",
    "advisory_url": "https://vendor.example/advisory"
  }]
}
```

This is a schema example, not an actual advisory or fixed-version claim. Supply
reviewed Debian, Ubuntu or Red Hat assertions. Native version ordering handles
epochs and distro revisions. The root's supplied `etc/os-release` must match the
snapshot vendor/release. Version assertions remain separate from byte-level
patch status, and feeds are never silently refreshed.

## Non-ELF and payload coverage

PE/Mach-O parsing validates file-backed mapped data, imports/exports, dependencies
and supported function metadata. Mach universal slices stay separate. PE
resource/certificate lookalikes and Wasm custom-section lookalikes do not count
as decoder tables. Wasm parsing preserves types, function indices, direct calls,
imports/exports and data initializer modes without instantiating the module.
Unsupported fixups, encryption, arm64e and Wasm features produce explicit gaps.

Regular ar/DEB, RPM/cpio, zstd and OCI/Docker save payloads use bounded streams or
sparse ranges. OCI final filesystems honor whiteouts and opaque directories;
historical layer evidence is not called shipped. Limits still apply to expanded
bytes, member counts and depth. These parsers never extract to host target paths.

Official paired Windows and macOS Brotli wheels exercise loader parsing and
table recognition. They do not supply a verified paired MSVC/Apple-clang
patch-code corpus. Those binaries remain patch-unresolved without stronger
independent evidence. The maintained native fixture verifier downloads only
when explicitly requested; normal scans never download samples.

## Reproducible reports and CI

Canonical JSON includes `evidence_envelope`: scanner source digest, effective
catalog/feed digests, analysis configuration, limits, tool distribution identities,
findings, relations and coverage. Scanner inputs are checked again after scanning;
a changed input prevents a complete comparison. Unavailable tools are recorded,
but only an attempted unavailable backend creates a coverage gap.

Use `--sarif` for a deterministic SARIF 2.1.0 view, or retain `--json` as the
baseline format. `--baseline /prior/report.json` verifies the prior report's
content hash and compares only compatible roots, catalogs, tools, configuration,
limits and complete coverage. Added/removed file counts can differ. Incomplete
or incompatible scans never label prior findings resolved/absent. Keep reports
outside scanned roots to avoid scanning the report itself.

`--fail-on affected`, `coverage`, or `new_affected` selects an explicit policy
and returns 1 when that policy fails, 0 otherwise. The default `none` preserves
the original CLI exit semantics. `new_affected` requires a complete comparable
baseline; failure to establish comparability fails the policy. A policy pass is
not an application-safety verdict. Output and baseline handling never upload data.
