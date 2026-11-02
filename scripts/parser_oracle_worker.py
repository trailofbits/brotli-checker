#!/usr/bin/env python3
"""Resource-limited worker for one parser differential observation."""

from __future__ import annotations

import argparse
import json
import resource
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("parser", choices=("scanner", "lief"))
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--memory-bytes", type=int, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (args.memory_bytes, args.memory_bytes))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "skills/brotli-checker/scripts"))
    from brotli_parser_oracles import lief_observation, scanner_observation  # noqa: PLC0415

    function = scanner_observation if args.parser == "scanner" else lief_observation
    print(json.dumps(function(args.fixture), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
