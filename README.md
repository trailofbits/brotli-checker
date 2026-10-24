# Brotli Checker

Brotli Checker finds copies of the Brotli decoder that may need an update for
[CVE-2026-111497](skills/brotli-checker/references/advisory.md). Install it as a
Claude Code or Codex skill, then ask it to check your project.

The skill scans source, dependencies, app packages, and unpacked container
filesystems. It checks source fingerprints and supported ELF binary code,
investigates which copies the app uses, and explains what to update or review.
Each copy keeps its own result.

For source review, [Trailmark](https://github.com/trailofbits/trailmark) maps calls
to the decoder and fetch APIs, helping the assistant find callers to inspect.
The scanner finds suspect parts; Trailmark helps show how the code connects.
The assistant checks whether those connections apply to the running app.

## Install and use

Ask Claude Code or Codex:

```text
Install the brotli-checker skill from https://github.com/trailofbits/brotli-checker/tree/main/skills/brotli-checker
```

For manual installation, copy the entire `skills/brotli-checker` folder into
`~/.claude/skills/` ([Claude Code](https://code.claude.com/docs/en/skills)) or
`~/.codex/skills/` (Codex). Start a new session, open the project to check, and ask:

```text
Use brotli-checker to check this project and tell me whether I need to update anything.
```

You can also name a folder or app package. With only a website address, the skill
explains what is missing and prepares a request for your hosting provider.
HTTP headers cannot establish the decoder's patch status.

Requires **Python 3.12–3.15** and [uv](https://docs.astral.sh/uv/) for Trailmark
source discovery. The standalone scanner uses only the standard library.

## Run the scanner directly

To collect local evidence without an agent:

```sh
git clone https://github.com/trailofbits/brotli-checker.git
cd brotli-checker
python3 skills/brotli-checker/scripts/brotli_inventory.py /path/to/application
```

The default output explains findings and next steps. Add `--json` for per-copy
evidence, coverage gaps, and a plain-language `user_summary`. See the
[scanner guide](docs/usage.md) for flags, exit codes, Trailmark source discovery,
binary inventory, and disassembly review.

## Understand the result

Affected code calls for an update or vendor-backport review. Version and
dependency findings need confirmation against the app's actual build. A fixed
copy does not clear other bundled copies, and an empty scan does not establish
that an app is safe.

The scanner reads files without executing application code or sending network
probes. Packaged compiled references cover x86, x86-64, ARM/Thumb, AArch64,
RISC-V64, PowerPC64 little-endian, s390x, MIPS32/64 in both byte orders, and
LoongArch64 ELF builds. Coverage depends on compiler and build flags; see the
[build matrix](docs/usage.md#compiled-decoder-evidence). Unsupported formats,
skipped files, and resource limits produce coverage gaps. Finding affected code does not establish that a
running app uses it or that an attacker can reach it.

Rules use an advisory snapshot dated **2026-10-23**. Check current vendor guidance
for updates and backports.

## Documentation

- [Scanner guide](docs/usage.md): commands, output, limits, and binary review.
- [Advisory](skills/brotli-checker/references/advisory.md): fixed versions,
  fingerprints, and provenance.
- [Reachability](skills/brotli-checker/references/reachability.md): investigating
  Node, Electron, Java, fonts, TLS, and compiled code.
- [Contributing](CONTRIBUTING.md): development setup and checks.
- [Security policy](SECURITY.md): private vulnerability reporting.

[MIT](LICENSE). Compiled Brotli references retain their
[upstream notices](skills/brotli-checker/references/THIRD_PARTY_NOTICES.md).
