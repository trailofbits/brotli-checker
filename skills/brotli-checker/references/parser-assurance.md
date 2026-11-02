# Parser differential assurance

Parser-oracle runs are development evidence, not target verdicts. Run them over
retained valid and malformed fixtures after layout-parser changes:

```sh
uv run --locked --extra assurance python scripts/run_parser_differential.py \
  --llvm-readobj /absolute/trusted/llvm-readobj \
  /absolute/valid-fixture /absolute/malformed-fixture
```

Each input is copied once from a stable non-symlink file descriptor into a
private immutable snapshot. The report binds its SHA-256 and size. Fixtures and
parsers run serially. The scanner and LIEF 1.0.0 each run in a fresh worker with
a 512 MiB address-space limit; every worker and an explicitly supplied absolute
`llvm-readobj` also use the process-group wall-time and output bounds from binary
triage. The report records the worker hash, LIEF version/module hash, and LLVM
executable hash/version output before parsing; a tool that changes during the run
is inconclusive.
Interrupted, resource-limited, unavailable, or invalid JSON oracle results are
inconclusive. This maintained assurance runner currently requires Linux resource
limits; ordinary scanner portability is unchanged.

The comparison records acceptance, format, architecture, word size, byte order,
and ELF executable-file ranges when the oracle exposes them. A scanner/oracle
disagreement is retained for investigation; it never changes detection or patch
state automatically. An oracle accepting a scanner-unsupported format is a
coverage gap, not proof that the oracle or input is correct. Preserve minimized
fixtures that reproduce resolved disagreements so future runs detect regressions.

LIEF is an assurance-only dependency. It is not imported by ordinary scans.
LLVM is deliberately an external trusted tool because its output schema and
binary provenance belong in the evidence record.

The maintained CI job builds the retained valid ELF source, preserves a malformed
PE fixture, installs LLVM from the signed runner distribution, and requires the
scanner, LIEF, and LLVM to agree on acceptance plus ELF format, architecture,
word size, byte order, and executable file ranges. Its report is retained as a
workflow artifact.
