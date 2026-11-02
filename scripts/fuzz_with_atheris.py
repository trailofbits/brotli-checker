#!/usr/bin/env python3
"""Coverage-guided adapter for the maintained parser fuzz entry points."""

from __future__ import annotations

import importlib
import importlib.metadata
import sys
from pathlib import Path
from typing import Any

PINNED_VERSION = "3.1.0"
HARNESSES = {
    "binary": "fuzz_binary_analysis",
    "package": "fuzz_package_provenance",
}
INSTRUMENTED_MODULES = {
    "binary": [
        "fuzz_binary_analysis",
        "brotli_binary_data",
        "brotli_binary_graph",
        "brotli_binary_layout",
        "brotli_binary_match",
        "brotli_debug_companions",
        "brotli_payloads",
    ],
    "package": [
        "fuzz_package_provenance",
        "brotli_package_provenance",
        "brotli_provenance",
    ],
}
ROOT = Path(__file__).resolve().parents[1]


def _load_atheris() -> Any:  # noqa: ANN401 -- Optional backend has no core dependency.
    try:
        backend = importlib.import_module("atheris")
        version = importlib.metadata.version("atheris")
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        msg = f"Atheris {PINNED_VERSION} is required for coverage-guided fuzzing"
        raise RuntimeError(msg) from error
    if version != PINNED_VERSION:
        msg = f"Atheris {PINNED_VERSION} is required; found {version}"
        raise RuntimeError(msg)
    return backend


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in HARNESSES:
        choices = "|".join(sorted(HARNESSES))
        print(
            f"usage: fuzz_with_atheris.py {{{choices}}} [atheris options/corpus]",
            file=sys.stderr,
        )
        return 2
    harness_name = arguments.pop(0)
    sys.path.insert(0, str(ROOT / "scripts"))
    sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
    atheris = _load_atheris()
    with atheris.instrument_imports(include=INSTRUMENTED_MODULES[harness_name]):
        harness = importlib.import_module(HARNESSES[harness_name])
    atheris.Setup([sys.argv[0], *arguments], harness.fuzz_one)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    sys.exit(main())
