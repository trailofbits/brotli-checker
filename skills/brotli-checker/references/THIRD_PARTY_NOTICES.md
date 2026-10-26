# Third-party notices

`binary-fingerprints.json.gz` contains compiled decoder text derived from Google
Brotli. The original copyright and MIT permission notice are retained in
[BROTLI-LICENSE](BROTLI-LICENSE). Keep this notice and license with the catalog
when redistributing the skill. Each reference records its source URL and hash,
compiler, build flags, ELF class/byte order, and object hash. New references also
record a hash of local header paths and contents. Source hashes may identify
identical decoder files shared by several release trees; they do not authenticate
surrounding headers or the full build environment.

`scripts/brotli_binary_signatures.py` also derives its decoder tables and command
table construction from Google Brotli's MIT-licensed `c/dec/decode.c`,
`c/dec/prefix.c`, and `c/dec/prefix_inc.h`. The same retained
[BROTLI-LICENSE](BROTLI-LICENSE) applies; provenance and independently verified
serialized digests are documented in [binary-signatures.md](binary-signatures.md).
