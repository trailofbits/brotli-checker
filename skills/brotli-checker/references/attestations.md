# Offline authenticated provenance

Use `--attestation bundle.json --attestation-policy trust.json` only with keys
whose authority the analyst has independently established. Both inputs are
captured once through stable, non-symlink file descriptors. Verification and
report identities consume those same immutable bytes; embedded URLs are never
fetched.

The supported profile is DSSE with `application/vnd.in-toto+json`, Ed25519, and
in-toto Statement/v1. A policy explicitly supplies base64-encoded 32-byte public
keys, a distinct-key threshold, and allowed predicate types:

```json
{
  "schema_version": 1,
  "public_keys": ["BASE64_ENCODED_TRUSTED_ED25519_PUBLIC_KEY"],
  "threshold": 1,
  "predicate_types": ["https://slsa.dev/provenance/v1"]
}
```

The placeholder above is not a usable key. No key supplied inside an attestation
becomes trusted. DSSE `keyid` is an unauthenticated hint; verification tries the
explicitly trusted keys and counts each key at most once. Duplicate signatures
cannot satisfy a multi-key threshold. Payload type and payload bytes are covered
by DSSE pre-authentication encoding. Duplicate JSON keys, nonfinite numbers,
oversized structures, malformed encodings and unsupported schemas are rejected.

A verified signature authenticates a statement. It does not establish the truth
of its predicate, the safety of the signing environment, or a Brotli patch state.
Only exact subject SHA-256 equality binds that statement to a scanned artifact;
subject names are not paths to open or alternative matching criteria. Every
attestation result leaves `patch_status` unknown. Vendor and embedded-copy
conclusions remain independent.

Reports preserve the exact captured policy/bundle input hashes and a separate
semantic policy fingerprint. Policy key ordering does not change the semantic
fingerprint. A missing crypto backend or invalid attestation yields an explicit
gap, never an unauthenticated success.

## Sigstore bundles

Sigstore verification uses a separately installed maintained verifier rather
than importing it into the scanner environment. `sigstore` 4.2.0 requires an
older `cryptography` range than the scanner's analysis backend, and weakening
the scanner dependency is not an acceptable integration. Version 4.2.0 is the
qualified profile and includes a bundle-digest consistency fix. A reproducible
isolated installation is:

```sh
UV_CACHE_DIR=/absolute/cache uv venv /absolute/sigstore-env --python 3.14
UV_CACHE_DIR=/absolute/cache uv pip install \
  --python /absolute/sigstore-env/bin/python sigstore==4.2.0
```

Supply an absolute verifier path, a captured Sigstore `ClientTrustConfig`, and a
local policy containing an exact certificate identity, OIDC issuer, evaluation
time, trust-config refresh deadline, maximum signature age, and future skew. The
scanner writes only the already-captured bundle and trust bytes to a private
temporary directory and invokes `verify identity` with `--offline` and the exact
scanned `sha256:` digest. It records the verifier path and hash before and after,
requires bounded `sigstore 4.2.0 --version` evidence, enforces the shared
process-group time/output limits, and never follows URLs or refreshes TUF. For a
Python console script, the executable hash identifies the launcher rather than
every module in its environment; reproduce the isolated installation from its
lock and cache when full environment identity matters. The bundle's untrusted
documented digest is used only to select a matching scanned artifact before
cryptographic verification; it is not evidence by itself.

The dedicated conformance CI installs the verifier in an isolated environment,
downloads Sigstore's `happy-path-v0.3` fixture at an immutable upstream commit,
checks the recorded bundle and artifact hashes, then requires both positive
offline verification and rejection of a validly encoded malicious digest change.

An offline result is relative to the captured trust configuration and explicit
evaluation time. The refresh deadline is a local policy assertion, not proof that
no later revocation exists. Sigstore's verified transparency-log time must also
fall inside the local freshness window. Signature success authenticates identity
and bytes, not the truth of a predicate or Brotli patch state.

## CycloneDX JSF

CycloneDX 1.x JSON Signature Format support verifies the single-signature
Ed25519 profile with externally trusted keys. It uses the maintained
`rfc8785==0.1.4` implementation for JCS canonicalization, deletes only the JSF
`value` member, and rejects `excludes`, extensions, multisignatures, chains,
certificate paths, other algorithms, ambiguous JSON, and embedded keys not in
the local policy. `keyId` is covered by this signature but does not select or
authorize a trusted key.

The signed CycloneDX `metadata.timestamp` is checked against the explicit local
evaluation and trust-refresh times. It is a signer-authenticated claim, not an
independent proof of signing time. Authenticated component SHA-256 values join
scanned artifacts only by exact digest. They remain authenticated BOM claims and
never promote patch status. Unsupported JSF profiles are gaps rather than
partially verified successes.

These paths do not provide an online revocation or freshness service. Merely
possessing a signed document is not proof that the signer remains authorized
today.

Primary contracts: [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md),
[in-toto Statement/v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
[Ed25519 backend](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/),
[Sigstore bundle format](https://docs.sigstore.dev/about/bundle/),
[Sigstore offline verification](https://sigstore.github.io/sigstore-python/advanced/offline/),
[JSF 0.82](https://cyberphone.github.io/doc/security/jsf.html), and
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html).
