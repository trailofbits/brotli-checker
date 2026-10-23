# Security policy

Report suspected vulnerabilities in brotli-checker privately through the secure
SendSafely link on [Trail of Bits' contact page](https://trailofbits.com/contact/).
Identify this repository and include the commit, Python version, command, and a
minimal reproduction. Redact credentials, customer data, and sensitive paths.
Please avoid public issues for undisclosed security problems.

For ordinary bugs, false positives, and feature requests, use
[GitHub issues](https://github.com/trailofbits/brotli-checker/issues). Include the
JSON evidence and coverage gaps where possible.

The current `main` branch receives fixes. Advisory rules and compiled references
are snapshots, and an old checkout does not automatically receive new guidance.
Use the latest revision and verify current upstream/vendor advisories.

The scanner reads untrusted local artifacts without executing them. Resource
limits reduce exposure to oversized inputs; they do not guarantee a complete
inventory. No result certifies an application safe. See
[scanner scope and limits](docs/usage.md#detection-and-traversal).
