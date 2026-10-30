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

This is not Sigstore keyless certificate/TUF/Rekor verification, CycloneDX JSF
verification, or a freshness/revocation service. Those require separate explicit
trust and offline-evidence policies; merely possessing a signed document is not
proof that the signer remains authorized today.

Primary contracts: [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md),
[in-toto Statement/v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md),
[Ed25519 backend](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
