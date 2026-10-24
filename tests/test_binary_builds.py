"""Optional offline integration tests against locally supplied upstream source trees.

BROTLI_TEST_SOURCES=/path/to/trees pytest tests/test_binary_builds.py
Trees must be named brotli-1.0.9, brotli-1.0.10, etc. Requires cc, ar, and strip;
compiles references and applications but never executes the applications.
"""

import json
import os
import runpy
import shlex
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/brotli-checker/scripts"))
import brotli_binary_match as matcher  # noqa: E402
from brotli_binary_triage import file_offset_address  # noqa: E402
from test_binary_inventory import run_scan  # noqa: E402

SOURCE_ROOT = os.environ.get("BROTLI_TEST_SOURCES")
pytestmark = pytest.mark.skipif(
    not SOURCE_ROOT, reason="Set BROTLI_TEST_SOURCES for real-build tests"
)
RELEASES = [
    ("1.0.9", "vulnerable"),
    ("1.0.10", "fixed"),
    ("1.1.0", "vulnerable"),
    ("1.1.1", "fixed"),
    ("1.2.0", "vulnerable"),
    ("1.2.1", "fixed"),
]
PACKAGED_REFERENCES = matcher.load_references(matcher.REFERENCES)


def invoke(command):
    subprocess.run(command, check=True, capture_output=True)  # noqa: S603 -- Local compiler tools, no targets executed.


def assert_packaged_match_if_compatible(data, reference, state):
    compatible = any(
        all(
            packaged.metadata.get(key) == reference.metadata.get(key)
            for key in ("compiler", "machine", "elf_class", "byteorder", "flags")
        )
        for packaged in PACKAGED_REFERENCES
    )
    if not compatible:
        return
    assessment = matcher.match_code(data, PACKAGED_REFERENCES)
    assert not assessment.limited
    assert assessment.matches
    assert {match["state"] for match in assessment.matches} == {state}
    assert any(
        match["source_sha256"] == reference.metadata["source_sha256"]
        and match["compiler"] == reference.metadata["compiler"]
        and match["flags"] == reference.metadata["flags"]
        for match in assessment.matches
    )


@pytest.mark.parametrize(("release", "state"), RELEASES)
@pytest.mark.parametrize("optimization", ["-O2", "-O3"])
@pytest.mark.parametrize("pic", [False, True])
def test_real_static_decoder(tmp_path, release, state, optimization, pic):  # noqa: PLR0915 -- End-to-end build/link/scan boundary.
    assert SOURCE_ROOT
    tree = Path(SOURCE_ROOT) / f"brotli-{release}"
    compiler = shutil.which(os.environ.get("BROTLI_TEST_CC", "cc"))
    archiver = shutil.which(os.environ.get("BROTLI_TEST_AR", "ar"))
    strip = shutil.which(os.environ.get("BROTLI_TEST_STRIP", "strip"))
    assert compiler
    assert archiver
    assert strip
    flags = [optimization, "-fPIC"] if pic else [optimization, "-fno-pic", "-fno-PIE"]
    flags.extend(shlex.split(os.environ.get("BROTLI_TEST_CFLAGS", "")))
    build = runpy.run_path(str(ROOT / "scripts/build_binary_references.py"))["build_references"]
    catalog = build([tree], compiler, flags)
    reference = matcher.CodeReference.from_json(catalog["references"][0])
    assert reference.metadata["state"] == state
    catalog_path = tmp_path / "references.json"
    catalog_path.write_text(json.dumps(catalog))
    objects = []
    for source in sorted([*(tree / "c/dec").glob("*.c"), *(tree / "c/common").glob("*.c")]):
        obj = tmp_path / (source.parent.name + "-" + source.stem + ".o")
        invoke([compiler, *flags, "-I", str(tree / "c/include"), "-c", str(source), "-o", str(obj)])
        objects.append(str(obj))
    library = tmp_path / "libdecoder.a"
    invoke([archiver, "rcs", str(library), *objects])
    main = tmp_path / "main.c"
    main.write_text(
        "#include <brotli/decode.h>\n"
        "int main(void) { unsigned char in[1] = {0}, out[1]; size_t n = 1;\n"
        "return (int)BrotliDecoderDecompress(1, in, &n, out); }\n"
    )
    addresses = []
    for link_flag in ("-no-pie", "-pie") if pic else ("-no-pie",):
        app = tmp_path / ("app" + link_flag)
        invoke(
            [
                compiler,
                *flags,
                *shlex.split(os.environ.get("BROTLI_TEST_LDFLAGS", "")),
                link_flag,
                "-I",
                str(tree / "c/include"),
                str(main),
                str(library),
                "-o",
                str(app),
            ]
        )
        invoke([strip, str(app)])
        data = app.read_bytes()
        assessment = matcher.match_code(data, [reference])
        assert not assessment.limited
        assert {m["state"] for m in assessment.matches} == {state}
        assert_packaged_match_if_compatible(data, reference, state)
        addresses.append(file_offset_address(data, assessment.matches[0]["file_offset"], 1))
        # Removing section headers must not change the answer.
        sectionless = bytearray(data)
        layout = matcher.ELFLayout.of(matcher.elf_header(data))
        small = layout.bits == 32
        struct.pack_into(
            ("<" if layout.byteorder == "little" else ">") + ("I" if small else "Q"),
            sectionless,
            32 if small else 40,
            0,
        )
        sectionless[46 if small else 58 : 52 if small else 64] = bytes(6)
        app.write_bytes(sectionless)
        result = run_scan(app, "--code-references", catalog_path)
        assert result.returncode == 1
        finding = json.loads(result.stdout)["findings"][0]
        assert finding["patch_status"] == state + "_code_match"
        assert finding["indicators"] == []
        assert app.read_bytes() == sectionless
        bundle = tmp_path / "app.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("bin/service", sectionless)
        result = run_scan(bundle, "--code-references", catalog_path)
        finding = json.loads(result.stdout)["findings"][0]
        assert finding["path"].endswith("!bin/service")
        assert finding["patch_status"] == state + "_code_match"
    if pic:
        assert addresses[0] != addresses[1]
