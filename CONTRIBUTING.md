# Contributing

Use Python 3.12–3.15 and [uv](https://docs.astral.sh/uv/) 0.13.5 or later. The
scanner itself uses only the standard library. Development, security, and mutation
tools are separate locked dependency groups.

## Checks

```sh
make dev
make lint
make test
make security
make mutations
```

`make lint` checks Ruff formatting, lint rules, and ty types; `make format`
applies formatting and lint fixes. The offline test suite runs on Python
3.12–3.15 in Linux CI and Python 3.12 on macOS, with an 80% combined line and
branch coverage floor.

`make security` runs zizmor's offline pedantic workflow checks and pip-audit
against the complete hashed lockfile export. Advisory queries require network
access.

`make mutations` uses pytest-gremlins with isolated subprocesses, fresh results,
and all default mutation operators. The gate requires at least an 80% score,
results from every scanner module, and no errors or skipped files. Only the
three standalone CLI bootstrap guards have pardons: inverting them launches
argparse during test collection. The gate checks their exact locations and
rejects other pardons. Standalone help tests cover the entry points. JSON and
HTML reports go to `coverage/gremlins/`. Confirmed mutation-induced timeouts
count as detections under pytest-gremlins' scoring.

Keep tests on the normal Python import path so mutation instrumentation runs.
Do not replace scanner imports with direct `exec_module` or `runpy.run_path`.
Keep the ordinary suite offline. Document optional downloads and trusted
compiler inputs separately.

## Reference and dependency updates

Preserve conservative results: fixed evidence for one copy must not clear an
unknown or affected copy. Source rules and compiled references need provenance
and positive/negative controls. Keep third-party notices with derived data.
Record validation commands, results, and limits in the pull request; keep local
run reports out of the repository.

To review dependency updates, run `uv lock --upgrade` and the checks above.
Resolution permits the latest stable releases; Dependabot proposals retain their
seven-day cooldown. Keep GitHub Actions pinned to full commit SHAs with exact
release comments.

### Compiled references

Generate catalogs from complete, trusted local upstream trees with an ELF
GCC-like compiler:

```sh
python3 scripts/build_binary_references.py /sources/brotli-1.2.0 /sources/brotli-1.2.1 \
  --cc cc --output compiled-references.json
```

Defaults compile `-O2` and `-O3`, each with PIC and non-PIC flags. Repeat
`--cflags='...'` for other profiles. The tool verifies `decode.c` against the
reviewed source registry, compiles without executing target code, and rejects
unsupported relocations/layouts. Headers, compiler, and flags remain trusted
inputs. It validates the finished catalog before atomically replacing output.
Generate the packaged catalog with this tool rather than editing it by hand.

## Optional validation

`make verify-fingerprints` downloads registered decoder sources, checks their
hashes and classifications, and checks modified variants. Downloaded source is
never executed.

Real ELF integration tests require `cc`, `ar`, `strip`, and six local upstream
trees named `brotli-1.0.9`, `brotli-1.0.10`, `brotli-1.1.0`, `brotli-1.1.1`,
`brotli-1.2.0`, and `brotli-1.2.1`:

```sh
BROTLI_TEST_SOURCES=/sources uv run --locked pytest tests/test_binary_builds.py --no-cov
```

Run on a Linux ELF build host. These tests exercise optimization/PIC profiles,
PIE/non-PIE links, stripped binaries, removed section headers, and archive
members. They never execute the resulting applications. Set
`BROTLI_LARGE_FILE_TESTS=1` when running the full suite to include the optional
multi-GiB hashing and CLI regressions.

### Runtime fixtures

These explicit maintainer fixtures use valid compressed responses on loopback.
They test decoding routes; they do not establish CVE triggerability, deployment
reachability, or a shipped decoder's patch state. The scanner never launches
them.

- **Node:** `make verify-node-fetch` checks built-in fetch, including an identity
  header and redirect, and records calls to Node's Brotli wrapper. Use a runtime
  that provides built-in fetch; CI uses Node 24.22.1.
- **Electron:** use an independently obtained, checksum-verified runtime embedding
  Node 24.5 or newer, with OpenSSL on PATH:

  ```sh
  env -u NODE_OPTIONS -u NODE_PATH -u ELECTRON_RUN_AS_NODE \
    BROTLI_CHECKER_OUTPUT=electron-result.json \
    /path/to/Electron.app/Contents/MacOS/Electron \
    "$PWD/skills/brotli-checker/scripts/verify_electron_fetch.cjs"
  ```

- **Slack on macOS:** quit normal Slack first, then run with Node 24 or newer and
  OpenSSL on PATH:

  ```sh
  env -u NODE_OPTIONS -u NODE_PATH \
    BROTLI_CHECKER_OUTPUT=slack-result.json \
    node scripts/verify_slack_renderer.cjs
  ```

  This fixture verifies `/Applications/Slack.app`'s signature, refuses to launch
  over an existing main process, and uses a fresh temporary profile in Slack's
  standard app container. It opens a local fixture through a loopback debugging
  connection and closes the test instance. Do not add a `sandbox-exec` wrapper.

Use a focused pull request describing the affected behavior, expected result,
and validation. Never include private application artifacts or credentials.
Follow [SECURITY.md](SECURITY.md) for sensitive reports.
