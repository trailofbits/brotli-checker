# Brotli Checker

Check your app for vulnerable Brotli copies and get clear steps to fix them.
The skill checks CVE-2026-111497, including copies bundled inside applications
and dependencies, and explains what it can confirm about the running app.

## Install and use the skill

Ask Codex:

```text
$skill-installer install the brotli-checker skill from https://github.com/trailofbits/brotli-checker/tree/main/skills/brotli-checker
```

Then ask:

```text
$brotli-checker check this project and tell me whether I need to update anything
```

You can provide a project folder, app package, or website address. The skill
gathers available evidence and gives a plain-language result and next action.
If a website address is not enough, it gives you a message to send to the person
who maintains or hosts the app.

A result might say:

> Vulnerable Brotli source found. We still need to check whether your app uses
> this copy. Ask the maintainer to update any affected copy used by the app,
> rebuild and deploy the app, and confirm that the running app has the fix.

For multiple copies, the answer identifies which ones need attention. A fixed
copy does not clear the others. If the result is inconclusive, the skill explains
what information is missing and who can get it.

## Run the checker directly

Supports Python 3.12–3.15; no extra Python packages are needed.

```sh
git clone https://github.com/trailofbits/brotli-checker.git
cd brotli-checker
python3 skills/brotli-checker/scripts/brotli_inventory.py /path/to/application
```

The checker reads local folders and common ZIP/JAR, WAR, wheel, and TAR archives.
It does not execute the application, load native libraries, or send probes.
Run it on source folders, app packages, or an unpacked container filesystem.
Pass several paths to check independent copies. Add `--json` for full technical
evidence and a plain-language `user_summary`.

You can also check an upstream version obtained separately:

```sh
python3 skills/brotli-checker/scripts/brotli_inventory.py --node-version 24.22.0
python3 skills/brotli-checker/scripts/brotli_inventory.py --brotli-version 1.1.1 --json
```

These flags check the supplied version; they do not identify the version used by
your running app. A package provider may have fixed an older version without
changing its upstream version number.

| Exit | Meaning |
| --- | --- |
| 0 | The reported files or supplied versions meet a known fix rule. The running app is unverified. |
| 1 | Vulnerable source or potentially affected source/version evidence was found. |
| 2 | Invalid command arguments. |
| 3 | More checking is needed, including no matches, unresolved candidates, or skipped files. |

## What the results establish

An exact source match identifies a decoder file. It does not prove that an app
builds, ships, or runs that file, or that an attacker can reach it. Dependency
names and binary symbols are leads that need further checking. Stripped or
statically linked binaries may require build records or binary analysis.

The checker reports skipped files and scan limits. It excludes `.git`, skips
symlinks, and does not resolve remote build inputs. No matches does not mean
that the app is safe. One fixed system library does not fix independent copies
included inside other applications.

The offline advisory snapshot was verified on **2026-10-23**. It contains 17
vulnerable decoder-file fingerprints and three fixed files, with source URLs and
hashes. See [advisory evidence](skills/brotli-checker/references/advisory.md) and
[guidance for investigating input paths](skills/brotli-checker/references/reachability.md).
The skill consults current vendor guidance when online research is available.

## Development

Use uv for development. The committed lockfile pins the development tools;
the installed skill still uses only Python's standard library.

```sh
uv sync --locked
uv run --locked ruff format --check .
uv run --locked ruff check .
uv run --locked ty check skills/brotli-checker/scripts scripts tests
uv run --locked pytest
```

CI runs the offline tests on Python 3.12, 3.13, 3.14, and 3.15, with an 80%
minimum for line and branch coverage combined. `make lint`, `make format`, and
`make test` run the same tools locally. The standalone inventory script also
declares its supported Python versions with PEP 723 metadata, so it can be run
with `uv run --script` after the skill is copied elsewhere.

To recheck the published source fingerprints and modified-source detection,
run this optional maintainer check, which downloads reference source but never
executes it:

```sh
uv run --locked python scripts/verify_fingerprints.py
```
