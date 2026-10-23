---
name: brotli-checker
description: Check whether an app or project needs a Brotli security update for CVE-2026-111497, explain the result in plain language, and give practical next steps. Find bundled copies and investigate whether the running app uses them.
---

# Check whether an app needs a Brotli update

Help someone who is not a security expert answer: "Does my app need an update,
and what should I do next?" They should be able to say "check this project" or
give a website address without knowing library versions, build details, or the
CVE number. Gather technical evidence yourself; translate it into a short,
actionable answer.

Assess CVE-2026-111497 for the requested source tree, application, or deployment.
Finding vulnerable source establishes source containment. Build selection,
shipment, attacker-controlled input reaching that decoder, and exploitability
are separate conclusions. Keep a result for each copy; one fixed copy cannot
clear other copies.

## Gather evidence

For "this project", start with the current project folder and discover its
application, dependencies, and deployment files. Use the supplied folder or
server access when available. Collect versions and package information with
trusted, read-only inspection tools; do not run application code or scripts
from the target. Do not make the user supply technical facts you can inspect.

Identify the target revision, build/platform, deployed artifact or container
digest, and the installation actually serving the application when available.
If only a URL is supplied, explain that headers and Brotli response support
cannot identify the decoder or its patch status. Say "I can't confirm this from
the website address alone" and give a short message the user can send to their
hosting provider asking it to check and update the app's Brotli decoder. If
the conversation already provides local/server access, use it. Ask only for
missing access or a target that cannot be inferred. Do not send malformed
streams or exploit probes.

From this skill's directory, run the offline inventory helper (Python 3.12–3.15).
Use JSON internally for the evidence; the default text output is for people:

```sh
python3 scripts/brotli_inventory.py /absolute/target --json
```

It reads files and bounded ZIP/JAR/WAR/wheel, TAR, gzip, bzip2, and XZ containers
without extracting them or executing target code. Known signatures identify
renamed archives and extensionless layers. Recognized unsupported formats such
as Debian, RPM, and Zstandard produce coverage gaps; provide unpacked files.
Signature-free or unrecognized encodings can be missed. Container traversal
does not reconstruct a final image filesystem. It checks eligible file bytes
against source fingerprints, identifies modified C decoder patterns, and records
dependency, native/Wasm, and JavaScript/TypeScript fetch/Undici candidates.
Fetch references include source locations; they are heuristic leads, not
confirmed Node calls or attacker-controlled inputs. Dependencies, build outputs, and hidden directories
are included; `.git` is excluded. Read its coverage gaps. It does not scan an
entire host, resolve remote dependencies, follow symlinks, prove binary patch
status, or establish an absence of Brotli. Supply extracted image filesystems
or additional artifact roots as needed. Filesystem symlink targets visited
directly do not add a gap; other targets still need checking. If a resource limit
is reached, scan a smaller relevant folder or adjust the limit shown by `--help`.

For independently obtained upstream versions, optional flags are:

```sh
python3 scripts/brotli_inventory.py --brotli-version 1.2.0 --json
python3 scripts/brotli_inventory.py --node-version 24.22.0 --json
```

These flags assess a supplied version string, not an installed or running build.
Never pass a wrapper package's version as the embedded Brotli version. Version
warnings allow vendor backports; prereleases, vendor suffixes, and branches
outside the snapshot's rules remain unknown. Exit 1 means affected-source or
version evidence; 3 means review/unknown; 0 means only the reported items meet
a known source fingerprint or upstream fixed-version rule; 2 means CLI error.
The helper never certifies the application safe.

End-of-life Node.js versions get supported-branch upgrade advice, while decoder
patch status remains unknown (exit 3) without build or vendor evidence.

Validation has covered decoder source references, synthetic packaging fixtures,
and a benign loopback test of built-in Node fetch response decompression.
No deployed application or binary was tested, and no malformed or exploit
payload was executed. The benign fetch test establishes a decoding route,
not CVE triggerability or exploitation. Do not describe source classification
as an end-to-end test of a vulnerable app.

## Establish patch status and reachability

Read [the advisory and detection reference](references/advisory.md) for source
provenance, fixed branches, backports, and detection limits. Verify current
vendor guidance if online research is available; otherwise date the assessment
to the packaged snapshot and flag that advisory freshness is unverified.

Inspect lockfiles, submodules, downloaded build inputs, native libraries inside
archives, linking configuration, SBOMs, and the shipped binary. Check all build
variants relevant to the deployment. Do not equate a dependency declaration or
an inventory entry with compilation or shipment. Stripped/static binaries need
build provenance, vendor evidence, or binary analysis; absence from a dynamic
library listing is insufficient. A fixed OS library does not fix embedded copies.

For each relevant surface, use [the reachability guide](references/reachability.md).
Trace the actual input entry point through middleware/wrappers to the selected
native decoder. Record configuration, authentication before decompression,
input ownership, and process boundaries. Consider inbound requests, outbound
responses, uploads and WOFF2/fonts, Java JNI stacks, workerd, and negotiated TLS
certificate compression. Pure Java/Rust implementations require their own
evidence; a language or algorithm name alone does not establish this C bug.

For Node.js apps, explicitly investigate built-in `fetch()`, `globalThis.fetch`,
and Undici wrappers, including attacker-controlled URLs and redirects. Automatic
Brotli response decoding can reach the native decoder without an explicit
Brotli dependency or `node:zlib` import. Establish the actual runtime's patch
state. The offline helper records source-reference and dependency leads, but
does not establish call paths, resolve fetch bindings, trace URL ownership,
or discover the running Node version. Review its locations and continue with
the Node/fetch section of the reachability guide. A fixed supplied version or
standalone Brotli library does not clear an unresolved runtime lead.

Report reachability as `confirmed`, `not_reachable_in_reviewed_configuration`,
or `unknown`, with paths/lines or deployment evidence. A negative conclusion
must name the exact configuration and reviewed paths. Missing evidence remains
unknown. Do not infer exploitability from reachability, CVSS, a crash, or a
third-party PoC.

## Explain the result and next action

Lead with a short answer that matches the evidence:

- "Update needed" when the app is confirmed to use an affected copy. State
  separately whether outside input can reach it.
- "Vulnerable Brotli source found" when affected code is present but its use by
  the running app is unknown. Say "We still need to check whether your app uses
  this copy." Do not label the whole app vulnerable from source presence alone.
- "Fix confirmed for the checked copy" when supported by verified evidence.
  State the scope; other copies and the running app may still need checking.
- "More information needed" when the result is inconclusive. Explain the
  specific missing information and who can obtain it.

Follow with what to do next. Name the affected component and the applicable
update when established, who should make it, and how to confirm the running app
has it. For a bundled copy, explain that the app must be rebuilt and deployed
again; updating the computer's shared library may leave that copy unchanged.
If action needs a maintainer or hosting provider, provide a short, ready-to-send
message with the specific finding and requested update/confirmation. Do not
send it yourself.

For several copies, use a small table: location, plain-language result, next
action. A fixed copy must not hide a vulnerable copy. Prioritize affected
shipped copies with confirmed untrusted input, then resolve other candidates.
State important unchecked files or missing running-app evidence in ordinary
language. An empty scan is inconclusive. Do not label it "safe" or "unaffected".

Keep the initial answer to a few sentences plus any useful short table. Avoid
raw status codes, hashes, long evidence columns, and unexplained terms such as
"shipment", "reachability", "JNI", or "provenance" in that answer. Preserve the
full per-copy evidence (patch confidence, build selection, shipped artifact,
input path, paths/lines, advisory date, and source/vendor links) for a maintainer
or a request for technical details. Do not make the user interpret a security
audit table to decide what to do.

Where an update cannot be deployed immediately, identify the specific receiving
decoder path that could be disabled and verify that boundary. Response encoding
settings alone do not establish that request, font, or certificate decoding is
disabled. Never present the community source inventory as vulnerable deployments.
