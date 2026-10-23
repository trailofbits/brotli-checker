"""Optional offline integration tests against locally supplied upstream source trees.

BROTLI_TEST_SOURCES=/path/to/trees pytest tests/test_binary_builds.py
Trees must be named brotli-1.0.9, brotli-1.0.10, etc. Requires cc, ar, and strip;
compiles references and applications but never executes the applications.
"""

import json
import os
import runpy
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


def invoke(command):
    subprocess.run(command, check=True, capture_output=True)  # noqa: S603 -- Local compiler tools, no targets executed.


@pytest.mark.parametrize(("release", "state"), RELEASES)
@pytest.mark.parametrize("pic", [False, True])
def test_real_static_decoder(tmp_path, release, state, pic):  # noqa: PLR0915 -- End-to-end build/link/scan boundary.
    assert SOURCE_ROOT
    tree = Path(SOURCE_ROOT) / f"brotli-{release}"
    compiler = shutil.which("cc")
    archiver = shutil.which("ar")
    strip = shutil.which("strip")
    assert compiler
    assert archiver
    assert strip
    flags = ["-O2", "-fPIC"] if pic else ["-O2", "-fno-pic", "-fno-PIE"]
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
    offsets = []
    for link_flag in ("-no-pie", "-pie") if pic else ("-no-pie",):
        app = tmp_path / ("app" + link_flag)
        invoke(
            [
                compiler,
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
        offsets.append(assessment.matches[0]["file_offset"])
        # Removing section headers must not change the answer.
        sectionless = bytearray(data)
        struct.pack_into("<Q", sectionless, 40, 0)
        sectionless[58:64] = bytes(6)
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
        assert offsets[0] != offsets[1]
