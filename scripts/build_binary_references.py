#!/usr/bin/env python3
"""Compile local, hash-verified Brotli decoder sources into ELF code references.

No downloads or target execution. Supply complete trusted upstream source trees;
only decode.c is compiled, with source identity/state from the reviewed registry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
from brotli_binary_match import reference_from_object  # noqa: E402


def build_references(trees: list[Path], compiler: str, flags: list[str]) -> dict:
    registry = json.loads((ROOT / "skills/brotli-checker/references/fingerprints.json").read_text())
    sources = {entry["sha256"]: entry for entry in registry["fingerprints"]}
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        msg = f"Compiler not found: {compiler}"
        raise ValueError(msg)
    version = subprocess.check_output([compiler_path, "--version"], text=True).splitlines()[0]  # noqa: S603
    references = []
    with tempfile.TemporaryDirectory(prefix="brotli-references-") as temporary:
        output = Path(temporary) / "decode.o"
        for tree in trees:
            source = tree.resolve() / "c/dec/decode.c"
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            if digest not in sources:
                msg = f"Unreviewed decoder source: {source} ({digest})"
                raise ValueError(msg)
            entry = sources[digest]
            command = [
                compiler_path,
                *flags,
                "-I",
                str(tree.resolve() / "c/include"),
                "-c",
                str(source),
                "-o",
                str(output),
            ]
            subprocess.run(command, check=True, capture_output=True)  # noqa: S603
            references.append(
                reference_from_object(
                    output.read_bytes(),
                    {
                        "id": f"{entry['sources'][0]['label']}:{version}:{shlex.join(flags)}",
                        "source_sha256": digest,
                        "source": entry["sources"][0]["url"],
                        "state": entry["state"],
                        "compiler": version,
                        "flags": shlex.join(flags),
                    },
                )
            )
    return {"schema_version": 1, "references": references}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trees", nargs="+", type=Path)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--cflags", action="append", help="repeat for multiple build profiles")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        profiles = args.cflags or ["-O2 -fno-pic -fno-PIE", "-O2 -fPIC"]
        result = {"schema_version": 1, "references": []}
        for profile in profiles:
            result["references"].extend(
                build_references(args.trees, args.cc, shlex.split(profile))["references"]
            )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
