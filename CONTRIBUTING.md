# Contributing

Use Python 3.12–3.15 and [uv](https://docs.astral.sh/uv/) 0.13.5 or later. The
scanner itself uses only the standard library. Development, security, and mutation
tools are separate locked dependency groups.

Before submitting a change:

```sh
make dev
make lint
make test
make security
make mutations
```

`make security` runs zizmor's offline pedantic workflow checks and pip-audit
against the complete hashed lockfile export. It needs network access for advisory
queries. `make mutations` uses pytest-gremlins with isolated subprocesses, fresh
results, and all default mutation operators. It requires at least an 80% score,
results from every scanner module, and no errors or skipped files. Only the two
CLI bootstrap guards have documented pardons: inverting them launches argparse
during test collection. The gate verifies those exact locations and rejects
other pardons. Standalone CLI help tests cover the real entry points.
JSON and HTML reports are written under `coverage/gremlins/`. Confirmed
mutation-induced timeouts count as detections under pytest-gremlins' scoring.

Keep tests on the normal Python import path so mutation instrumentation runs.
Do not replace scanner imports with direct `exec_module` or `runpy.run_path`.
Keep the ordinary test suite offline; document optional downloads and trusted
compiler inputs separately. Source fingerprint verification and the benign Node
fetch probe are available through `make verify-fingerprints` and
`make verify-node-fetch`. Real ELF build tests require a Linux ELF compiler and
local upstream source trees; see the README.

Preserve conservative results: fixed evidence for one copy must not clear an
unknown or affected copy. Changes to source rules or compiled references need
provenance and positive/negative controls. Keep third-party notices with derived
reference data. Record validation scope and limits in `docs/validation.md`.

To review dependency updates, run `uv lock --upgrade` and all checks above.
Resolution permits the latest stable releases; Dependabot proposals retain their
seven-day cooldown. Review lockfile changes and keep GitHub Actions pinned to
full commit SHAs with exact release comments.

Use a focused pull request describing the affected behavior, expected result,
and validation. Never include private application artifacts or credentials.
Follow [SECURITY.md](SECURITY.md) for sensitive reports.
