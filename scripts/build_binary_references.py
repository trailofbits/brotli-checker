#!/usr/bin/env python3
"""Compile local, hash-verified Brotli decoder sources into ELF code references.

No downloads or target execution. Supply complete trusted upstream source trees;
only decode.c is compiled, with source identity/state from the reviewed registry.
"""

from __future__ import annotations

import argparse
import gzip
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
from brotli_binary_match import load_references, reference_from_object  # noqa: E402


def scoped_reference_id(reference: dict) -> str:
    identifier = (
        f"{reference['machine']}:{reference['elf_class']}:"
        f"{reference['byteorder']}:{reference['id']}"
    )
    if scope := reference.get("code_scope"):
        identifier += f":scope={scope}"
    return identifier


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
            headers = hashlib.sha256()
            for path in sorted((tree.resolve() / "c").rglob("*.h")):
                headers.update(path.relative_to(tree.resolve()).as_posix().encode() + b"\0")
                headers.update(hashlib.sha256(path.read_bytes()).digest())
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
            reference = reference_from_object(
                output.read_bytes(),
                {
                    "id": f"{entry['sources'][0]['label']}:{version}:{shlex.join(flags)}",
                    "source_sha256": digest,
                    "source": entry["sources"][0]["url"],
                    "state": entry["state"],
                    "compiler": version,
                    "flags": shlex.join(flags),
                    "headers_sha256": headers.hexdigest(),
                },
                section_scope="auto",
            )
            reference["id"] = scoped_reference_id(reference)
            references.append(reference)
    return {"schema_version": 1, "references": references}


def unique_references(references: list[dict]) -> list[dict]:
    unique = {}
    for reference in references:
        identifier = reference.get("id")
        if not isinstance(identifier, str) or not identifier:
            msg = "Generated code reference has no valid id"
            raise ValueError(msg)
        if identifier in unique:
            if unique[identifier] != reference:
                msg = f"Conflicting generated code reference id: {identifier}"
                raise ValueError(msg)
            continue
        unique[identifier] = reference
    return list(unique.values())


def write_validated_catalog(output: Path, catalog: dict) -> None:
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            data = (json.dumps(catalog, indent=2) + "\n").encode()
            if output.suffix == ".gz":
                with gzip.GzipFile(
                    filename="", mode="wb", compresslevel=9, fileobj=stream, mtime=0
                ) as compressed:
                    compressed.write(data)
            else:
                stream.write(data)
        load_references(temporary_path)
        temporary_path.replace(output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trees", nargs="*", type=Path)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--cflags", action="append", help="repeat for multiple build profiles")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-note", help="record provenance on newly compiled references")
    parser.add_argument(
        "--merge", action="append", default=[], type=Path, help="merge a validated catalog"
    )
    args = parser.parse_args()
    if not args.trees and not args.merge:
        parser.error("provide source trees or --merge catalogs")
    try:
        profiles = args.cflags or [
            "-O2 -fno-pic -fno-PIE",
            "-O2 -fPIC",
            "-O3 -fno-pic -fno-PIE",
            "-O3 -fPIC",
        ]
        result = {"schema_version": 1, "references": []}
        for profile in profiles if args.trees else []:
            result["references"].extend(
                build_references(args.trees, args.cc, shlex.split(profile))["references"]
            )
        if args.build_note:
            for reference in result["references"]:
                reference["build_note"] = args.build_note
        for catalog in args.merge:
            result["references"].extend(ref.to_json() for ref in load_references(catalog))
        result["references"] = unique_references(result["references"])
        write_validated_catalog(args.output, result)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
