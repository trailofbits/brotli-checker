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

### Exit codes

For automation, use the exit code together with the JSON evidence:

| Exit | Meaning |
| --- | --- |
| 0 | The reported files or supplied versions meet a known fix rule. This does not confirm the running app is fixed. |
| 1 | Vulnerable source or potentially affected source/version evidence was found. |
| 2 | Invalid command arguments. |
| 3 | More checking is needed, including no matches, unresolved candidates, or skipped files. |

## Detection and scope

The scanner checks file contents against reviewed source fingerprints, flags
modified C decoder patterns, and collects dependency names and binary symbols
as leads. It reads local folders and bounded ZIP/JAR, WAR, wheel, and TAR
archives without extracting them or executing application code.

An exact match identifies a decoder source file. Dependency names and binary
symbols alone do not establish whether a component contains the affected code.
Stripped or statically linked binaries may require build records, vendor
evidence, or binary analysis. The scanner cannot establish which copy a running
process uses or whether an attacker can reach it.

Hidden folders, dependencies, and build outputs are included. The scanner
excludes `.git`, skips symlinks, and reports files it could not inspect and
limits it reached. It does not resolve remote build inputs, load native
libraries, or send network probes.

The offline advisory snapshot was verified on **2026-10-23**. It contains 17
vulnerable decoder-file fingerprints and three fixed files, with source URLs and
hashes. This is a source inventory, not a count of vulnerable applications.
The scanner uses this packaged snapshot; the skill consults current vendor
guidance when online research is available.

- [Advisory, fixed versions, and fingerprint provenance](skills/brotli-checker/references/advisory.md)
- [Investigating HTTP, Java, WOFF2, workerd, and TLS input paths](skills/brotli-checker/references/reachability.md)
- [Skill instructions](skills/brotli-checker/SKILL.md)

## Development

Use uv for development. The committed lockfile pins the development tools;
the installed skill still uses only Python's standard library.
Dependency resolution waits one week before accepting new package uploads.

```sh
uv sync --locked
make lint
make test
```

CI runs the offline tests on Python 3.12, 3.13, 3.14, and 3.15, with an 80%
minimum for line and branch coverage combined. `make lint` checks Ruff formatting,
Ruff lint rules, and ty types; `make format` applies formatting and lint fixes.
The underlying uv commands and tool settings are in the [Makefile](Makefile)
and [pyproject.toml](pyproject.toml).

The inventory script declares its supported Python versions with PEP 723
metadata. It can also run through `uv run --script` after the skill is copied
elsewhere.

To recheck the published source fingerprints and modified-source detection,
run this optional maintainer check, which downloads reference source but never
executes it:

```sh
uv run --locked python scripts/verify_fingerprints.py
```
