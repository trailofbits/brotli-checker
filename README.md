# Brotli Checker

Find vulnerable Brotli copies in your project and get clear steps to address
them. Brotli Checker is a Codex skill for **CVE-2026-111497**, with an offline
Python scanner you can also run directly.

The skill gathers evidence, investigates whether the running app uses a flagged
copy, and explains the next action in plain language. You do not need to know
your Brotli version or understand the vulnerability to start.

**Finding vulnerable source does not, by itself, prove that an app is vulnerable.**
Each copy needs its own check, including copies bundled into dependencies or
statically linked into an application.

## Check a project with Codex

Open your project in Codex and ask it to install the skill:

```text
$skill-installer install the brotli-checker skill from https://github.com/trailofbits/brotli-checker/tree/main/skills/brotli-checker
```

Once it is installed, send this as your next message:

```text
$brotli-checker check this project and tell me whether I need to update anything
```

The skill starts with the current project. You can also name a specific folder
or app package.

| What you have | What the skill can do |
| --- | --- |
| Source code and dependencies | Find decoder copies and investigate which ones the app builds and uses. |
| An app package or unpacked container filesystem | Inspect available files and nested archives; identify components that need build records or further analysis. |
| Only a website address | Explain what cannot be confirmed remotely and prepare a message for your maintainer or hosting provider. |

A website's Brotli support or response headers cannot identify its decoder or
confirm that it has the fix.

## Understand the result

An illustrative skill response:

> Vulnerable Brotli source found in `vendor/brotli/c/dec/decode.c`. We still
> need to check whether your app uses this copy. Ask the maintainer to update
> any affected copy used by the app, rebuild and deploy the app, and confirm
> that the running app has the fix.

For several copies, the skill reports each one's result and next action. If
someone else needs to make the change, it provides a ready-to-send message.

| Result | What to do next |
| --- | --- |
| Update needed: the app uses an affected copy | Update that component, rebuild and deploy as needed, and verify the running app uses the fix. |
| Source or a supplied version needs review | Have a maintainer confirm which copy the app uses and whether it includes a vendor fix. |
| Fix identified in the checked items | Confirm the running app uses those items and check any other bundled copies. |
| More information needed, no matches, or skipped files | Resolve the missing evidence or scan gaps with the maintainer. An empty scan does not establish that the app is safe. |

Updating a computer's shared Brotli library may leave copies inside apps
unchanged. Confirming that an app uses affected code is also separate from
confirming whether outside input can reach it or whether it can be exploited.

## Run the scanner directly

The scanner collects local evidence without an AI agent. It supports
**Python 3.12–3.15** and needs no extra Python packages.

```sh
git clone https://github.com/trailofbits/brotli-checker.git
cd brotli-checker
python3 skills/brotli-checker/scripts/brotli_inventory.py /path/to/application
```

Pass a source folder, app package, or unpacked container filesystem. The default
output gives a plain-language result and next steps. For a report to share with
a maintainer or use in automation, add `--json`:

```sh
python3 skills/brotli-checker/scripts/brotli_inventory.py /path/to/application --json
```

| Option | Use |
| --- | --- |
| `PATH ...` | Check one or more folders or app packages; defaults to the current folder. |
| `--json` | Include full evidence, per-copy status, scan gaps, and a plain-language `user_summary`. |
| `--node-version VERSION` | Check a separately obtained upstream Node.js version against the packaged fix rules. |
| `--brotli-version VERSION` | Check a separately obtained upstream Brotli version against the packaged fix rules. |
| `--help` | Show file-size, total-read, file-count, and archive-depth limits. |

For example, to check a version you already obtained:

```sh
python3 skills/brotli-checker/scripts/brotli_inventory.py --node-version 24.22.0
python3 skills/brotli-checker/scripts/brotli_inventory.py --brotli-version 1.1.1 --json
```

Version flags do not discover what your running app uses. For `--brotli-version`,
supply the embedded library's version rather than a wrapper package's version.
A provider may also have fixed an older release without changing its upstream
version number.

End-of-life Node.js branches get advice to move to a supported fixed release.
Their decoder patch status remains unknown without build or vendor evidence.
This advice uses the dated advisory snapshot, so check current vendor guidance.

Node's built-in `fetch()` can reach Brotli through automatic response decoding,
even without a Brotli package in the app's dependencies. The skill investigates
that route using the [Node/fetch guide](skills/brotli-checker/references/reachability.md#nodes-built-in-fetch).
The offline scanner records fetch references in JavaScript/TypeScript and
Undici imports or dependency declarations, with source locations and runtime
verification steps. These are review leads: a browser, custom fetch binding,
or unused dependency can produce a match. It does not trace URL ownership or
discover the running Node version; provide that runtime's version with
`--node-version`. A supplied fixed version does not clear an unresolved fetch lead.

### Exit codes

For automation, use the exit code together with the JSON evidence:

| Exit | Meaning |
| --- | --- |
| 0 | The reported files or supplied versions meet a known fix rule and no recognized scan gaps were recorded. This does not confirm the running app is fixed. |
| 1 | Vulnerable source or potentially affected source/version evidence was found. |
| 2 | Invalid command arguments. |
| 3 | More checking is needed, including no matches, unresolved candidates, or skipped files. |

## Detection and scope

The scanner checks file contents against reviewed source fingerprints, flags
modified C decoder patterns, and collects dependency names and binary symbols
as leads. It also flags fetch/Undici references in `.js`, `.mjs`, `.cjs`, `.jsx`,
`.ts`, `.mts`, `.cts`, and `.tsx` files, including archive members. This bounded
heuristic skips comments and ordinary string mentions; it preserves template
literals to retain expressions, which can produce extra leads. It does not
parse JavaScript, resolve bindings, or guarantee discovery of computed,
obfuscated, bundled, or dynamically generated calls.

It reads local folders and bounded ZIP/JAR, WAR, wheel, and TAR
archives without extracting them or executing application code. Known content
signatures identify renamed archives and extensionless container layers.
Gzip, bzip2, and XZ streams are expanded within the same limits, including when
their names do not identify their compression format.

Recognized unsupported formats, including Debian/AR and RPM packages, Zstandard,
7z, and RAR, are reported as gaps. Provide unpacked files to inspect their
contents. Signature-free or unrecognized encodings can still be missed; an
arbitrary file cannot always be identified as compressed. Container layer
traversal does not reconstruct the final image filesystem or resolve whiteouts.

An exact match identifies a decoder source file. Dependency names and binary
symbols alone do not establish whether a component contains the affected code.
Stripped or statically linked binaries may require build records, vendor
evidence, or binary analysis. The scanner cannot establish which copy a running
process uses or whether an attacker can reach it.

Hidden folders, dependencies, and build outputs are included. The scanner
excludes `.git`, skips symlinks, and reports files it could not inspect and
limits it reached. A filesystem symlink does not add a gap when its resolved
target was checked directly among the supplied scan roots. External,
broken, and otherwise unchecked targets remain gaps; archive links remain gaps.
It does not resolve remote build inputs, load native libraries, or send network
probes. Text output quotes paths and escapes control characters and non-ASCII
characters; JSON retains the original labels as escaped strings.

If a large tree hits a limit, scan a smaller relevant folder or use
`--max-file-bytes`, `--max-total-bytes`, `--max-files`, or `--archive-depth`.
The defaults are 16 MiB per file/expanded stream, 256 MiB total, 50,000 files or
members, and two archive levels. The total includes reading the container,
decompression, and reading its members. Increasing a limit increases resource
use; skipped files keep the result incomplete.

JSON records total, retained, and omitted gap-detail counts. It distinguishes
archive inspection attempts from successful opens. Unresolved container markers
are displayed separately from member candidates; a marker visible through a
stored archive is not counted as another decoder copy.

The offline advisory snapshot was verified on **2026-10-23**. It contains 17
vulnerable decoder-file fingerprints and three fixed files, with source URLs and
hashes. This is a source inventory, not a count of vulnerable applications.
The scanner uses this packaged snapshot; the skill consults current vendor
guidance when online research is available.

- [Advisory, fixed versions, and fingerprint provenance](skills/brotli-checker/references/advisory.md)
- [Investigating HTTP, Java, WOFF2, workerd, and TLS input paths](skills/brotli-checker/references/reachability.md)
- [Skill instructions](skills/brotli-checker/SKILL.md)

## Validation scope

The vulnerable reference target was **Google Brotli v1.2.0's `c/dec/decode.c`**,
with v1.0.10's fixed decoder source as a control. Both classified as expected.
The full fingerprint verifier checks 20 source files and modified variants.

An additional benign loopback probe confirmed that built-in Node fetch invokes
the Brotli decoder for valid HTTP responses, including with an identity request
header and after a redirect.

**No deployed application or binary was tested, and no malformed or exploit
payload was executed.** Automated archive tests use synthetic packaging fixtures.
These checks establish source detection, scanner behavior, and the local fetch
decoding route. They do not establish application exposure, exploitability,
or inventory completeness.
See [the validation record](docs/validation.md) for hashes, commands, and limits.

## Development

Use uv for development. The committed lockfile pins the development tools;
the installed inventory helper still uses only Python's standard library.
Dependency resolution waits one week before accepting new package uploads.

```sh
uv sync --locked
make lint
make test
```

CI runs the offline tests on Python 3.12, 3.13, 3.14, and 3.15, with an 80%
minimum for line and branch coverage combined. `make lint` checks Ruff formatting,
Ruff lint rules, and ty types; `make format` applies formatting and lint fixes.
CI also runs the benign built-in fetch probe on Node.js 24.22.1.
The underlying uv commands and tool settings are in the [Makefile](Makefile)
and [pyproject.toml](pyproject.toml).

The inventory script declares its supported Python versions with PEP 723
metadata. It can also run through `uv run --script` after the skill is copied
elsewhere.

The repository and the independently installed skill are distributed under the
[MIT license](LICENSE).

To recheck the published source fingerprints and modified-source detection,
run this optional maintainer check, which downloads reference source but never
executes it:

```sh
uv run --locked python scripts/verify_fingerprints.py
```

To repeat the benign built-in Node fetch check, use a Node runtime that provides
fetch. It serves valid Brotli responses on loopback and checks both the decoded
body and calls to Node's Brotli wrapper:

```sh
make verify-node-fetch
```
