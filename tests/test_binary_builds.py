"""Optional offline integration tests against locally supplied upstream source trees.

BROTLI_TEST_SOURCES=/path/to/trees pytest tests/test_binary_builds.py
Trees must be named brotli-1.0.9, brotli-1.0.10, etc. Requires cc, ar, and strip;
compiles references and applications. Targets are executed only when the caller
explicitly supplies BROTLI_TEST_RUNNER (for example, QEMU plus its -L sysroot).
Set BROTLI_TEST_GC_SECTIONS=1 to add function/data sections and linker GC, and
to exercise patch-role retention plus a version-only missing-role control.
"""

import contextlib
import io
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
import brotli_inventory as scanner  # noqa: E402
from brotli_binary_triage import file_offset_address  # noqa: E402
from test_binary_inventory import run_scan  # noqa: E402

SOURCE_ROOT = os.environ.get("BROTLI_TEST_SOURCES")
RUNTIME_TIMEOUT_SECONDS = 10
COMPRESSED_PAYLOAD = bytes.fromhex(
    "1b1f00f88d94abed6821a427eb4a128a9a4c30ecdbaf64092aa439e2b73d0929363a4c19"
)
EXPECTED_PLAINTEXT = b"Brotli cross-architecture smoke\n"
RELEASES = [
    ("1.0.9", "vulnerable"),
    ("1.0.10", "fixed"),
    ("1.1.0", "vulnerable"),
    ("1.1.1", "fixed"),
    ("1.2.0", "vulnerable"),
    ("1.2.1", "fixed"),
]
PAIRED_RELEASE = {
    "1.0.9": "1.0.10",
    "1.0.10": "1.0.9",
    "1.1.0": "1.1.1",
    "1.1.1": "1.1.0",
    "1.2.0": "1.2.1",
    "1.2.1": "1.2.0",
}
REFERENCE_CATALOG = Path(os.environ.get("BROTLI_TEST_REFERENCE_CATALOG", str(matcher.REFERENCES)))
PACKAGED_REFERENCES = matcher.load_references(REFERENCE_CATALOG)
GC_COMPILE_FLAGS = ("-ffunction-sections", "-fdata-sections")
GC_LINK_FLAGS = ("-Wl,--gc-sections",)
PATCH_ROLES = {
    "literal",
    "command",
    "distance",
    "safe_literal",
    "safe_command",
    "safe_distance",
    "process",
    "safe_process",
    "helpers",
}
UNRELATED_DECODER_APIS = {
    "BrotliDecoderAttachDictionary",
    "BrotliDecoderErrorString",
    "BrotliDecoderGetErrorCode",
    "BrotliDecoderHasMoreOutput",
    "BrotliDecoderIsFinished",
    "BrotliDecoderIsUsed",
    "BrotliDecoderSetMetadataCallbacks",
    "BrotliDecoderSetParameter",
    "BrotliDecoderTakeOutput",
}


def invoke(command):
    subprocess.run(command, check=True, capture_output=True)  # noqa: S603 -- Local compiler tools, no targets executed.


def configured_runner(value):
    if value is None:
        return None
    command = shlex.split(value)
    if not command:
        msg = "BROTLI_TEST_RUNNER must contain a runner command"
        raise ValueError(msg)
    return command


def configured_boolean(value, name):
    if value is None:
        return False
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    msg = f"{name} must be one of 1/0, true/false, or yes/no"
    raise ValueError(msg)


def expected_runtime_output(release):
    return f"ok version={release} bytes={len(EXPECTED_PLAINTEXT)}\n"


def run_runtime_smoke(app, release, runner, *, expected_output=None):
    if runner is None:
        return
    command = [*runner, str(app)]
    try:
        result = subprocess.run(  # noqa: S603 -- Explicit opt-in trusted runner and built fixture.
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=RUNTIME_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        message = f"runtime smoke timed out after {RUNTIME_TIMEOUT_SECONDS}s: {command!r}"
        raise AssertionError(message) from error
    assert result.returncode == 0, (
        f"runtime smoke exited {result.returncode}: command={command!r} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    if expected_output is None:
        expected_output = expected_runtime_output(release)
    assert result.stdout == expected_output, (
        f"runtime smoke output mismatch: command={command!r} "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert result.stderr == "", (
        f"runtime smoke wrote stderr: command={command!r} stderr={result.stderr!r}"
    )


def c_array(data):
    return ", ".join(f"0x{value:02x}" for value in data)


def runtime_harness_source(release):
    major, minor, patch = map(int, release.split("."))
    encoded = major << 24 | minor << 12 | patch
    return f"""
#include <brotli/decode.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t compressed[] = {{{c_array(COMPRESSED_PAYLOAD)}}};
static const uint8_t expected[] = {{{c_array(EXPECTED_PLAINTEXT)}}};

static int check_one_shot(void) {{
  uint8_t output[sizeof(expected) + 32];
  size_t output_size = sizeof(output);
  BrotliDecoderResult result = BrotliDecoderDecompress(
      sizeof(compressed), compressed, &output_size, output);
  return result == BROTLI_DECODER_RESULT_SUCCESS &&
      output_size == sizeof(expected) && !memcmp(output, expected, sizeof(expected));
}}

static int check_streaming(void) {{
  BrotliDecoderState* state = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  const uint8_t* next_in = NULL;
  size_t available_in = 0;
  size_t input_offset = 0;
  uint8_t output[sizeof(expected) + 32];
  uint8_t* next_out = output;
  size_t available_out = sizeof(output);
  size_t total_out = 0;
  unsigned int calls = 0;
  BrotliDecoderResult result = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
  if (state == NULL) return 0;
  while (result != BROTLI_DECODER_RESULT_SUCCESS && calls++ < 1024) {{
    if (available_in == 0 && input_offset < sizeof(compressed)) {{
      size_t chunk = sizeof(compressed) - input_offset;
      if (chunk > 3) chunk = 3;
      next_in = compressed + input_offset;
      available_in = chunk;
      input_offset += chunk;
    }}
    result = BrotliDecoderDecompressStream(
        state, &available_in, &next_in, &available_out, &next_out, &total_out);
    if (result == BROTLI_DECODER_RESULT_ERROR ||
        (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT &&
         available_in == 0 && input_offset == sizeof(compressed)) ||
        (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT && available_out == 0)) {{
      BrotliDecoderDestroyInstance(state);
      return 0;
    }}
  }}
  BrotliDecoderDestroyInstance(state);
  return result == BROTLI_DECODER_RESULT_SUCCESS && available_in == 0 &&
      input_offset == sizeof(compressed) && total_out == sizeof(expected) &&
      !memcmp(output, expected, sizeof(expected));
}}

int main(void) {{
  uint32_t version = BrotliDecoderVersion();
  if (version != UINT32_C({encoded})) return 20;
  if (!check_one_shot()) return 21;
  if (!check_streaming()) return 22;
  printf("ok version=%u.%u.%u bytes=%zu\\n",
      version >> 24, (version >> 12) & 0xfff, version & 0xfff, sizeof(expected));
  return 0;
}}
""".lstrip()


def version_harness_source(release):
    major, minor, patch = map(int, release.split("."))
    encoded = major << 24 | minor << 12 | patch
    return f"""
#include <brotli/decode.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {{
  uint32_t version = BrotliDecoderVersion();
  if (version != UINT32_C({encoded})) return 20;
  printf("version-only ok version=%u.%u.%u\\n",
      version >> 24, (version >> 12) & 0xfff, version & 0xfff);
  return 0;
}}
""".lstrip()


def defined_function_symbols(data):
    header = matcher.elf_header(data)
    sections = matcher.section_headers(data, header)
    symbols = set()
    for table in sections:
        if table[1] not in (matcher.SHT_SYMTAB, matcher.SHT_DYNSYM):
            continue
        strings = sections[table[6]]
        string_start = strings[4]
        string_end = string_start + strings[5]
        for name_offset, info, _, index, _, _ in matcher.symbol_rows(data, header, table):
            if info & 0xF != matcher.STT_FUNC or index == 0 or name_offset >= strings[5]:
                continue
            start = string_start + name_offset
            end = data.find(b"\0", start, string_end)
            if end >= 0:
                symbols.add(data[start:end].decode("ascii"))
    return symbols


def patch_function_names(reference):
    functions = reference.metadata["patch_functions"]
    assert set(functions) == PATCH_ROLES
    assert all(functions[role] for role in PATCH_ROLES - {"helpers"})
    return {name for names in functions.values() for name in names}


def assert_gc_population(path, reference, discarded):
    assert reference.metadata["code_scope"] == matcher.REFERENCE_SCOPE_PATCH
    linked = defined_function_symbols(path.read_bytes())
    assert patch_function_names(reference) <= linked
    assert discarded
    assert discarded.isdisjoint(linked)


def profile_value(metadata, key):
    if key == "elf_class":
        return metadata.get(key, 64)
    if key == "byteorder":
        return metadata.get(key, "little")
    return metadata.get(key)


def packaged_match_evidence(data, reference, state, *, required):
    compatible = any(
        all(
            profile_value(packaged.metadata, key) == profile_value(reference.metadata, key)
            for key in ("compiler", "machine", "elf_class", "byteorder", "flags")
        )
        for packaged in PACKAGED_REFERENCES
    )
    assessment = matcher.match_code(data, PACKAGED_REFERENCES)
    assert all(match["state"] == state for match in assessment.matches), (
        "packaged references must never identify the opposite state"
    )
    if compatible:
        assert not assessment.limited
        assert assessment.matches
        assert any(
            match["source_sha256"] == reference.metadata["source_sha256"]
            and match["compiler"] == reference.metadata["compiler"]
            and match["flags"] == reference.metadata["flags"]
            for match in assessment.matches
        )
        return "exact packaged compiler/profile matched"
    if required:
        pytest.fail(
            "BROTLI_TEST_REQUIRE_PACKAGED requires an exact packaged compiler/profile match: "
            f"compiler={reference.metadata['compiler']!r} flags={reference.metadata['flags']!r}"
        )
    return (
        "local compiler/profile is outside packaged provenance; "
        f"same_state_matches={len(assessment.matches)} reason={assessment.reason}"
    )


def run_main_scan(path, catalog_path):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = scanner.main([str(path), "--code-references", str(catalog_path), "--json"])
    return code, json.loads(output.getvalue())


def assert_missing_gc_population(  # noqa: PLR0913, PLR0917 -- Complete negative boundary.
    path, reference, references, state, catalog_path, runner, release
):
    data = path.read_bytes()
    linked = defined_function_symbols(data)
    assert patch_function_names(reference).isdisjoint(linked)
    local = matcher.match_code(data, references)
    assert not local.limited
    assert local.patch_status == "unknown"
    assert local.matches == []
    packaged = matcher.match_code(data, PACKAGED_REFERENCES)
    assert packaged.matches == []

    main_code, report = run_main_scan(path, catalog_path)
    version_supported = reference.metadata["machine"] in {
        matcher.EM_386,
        matcher.EM_X86_64,
        matcher.EM_AARCH64,
    }
    assert main_code == (1 if state == "vulnerable" and version_supported else 3)
    assert all(not item["patch_status"].endswith("_code_match") for item in report["findings"])
    run_runtime_smoke(
        path,
        release,
        runner,
        expected_output=f"version-only ok version={release}\n",
    )


def assert_artifact(  # noqa: PLR0913, PLR0917 -- One complete per-artifact acceptance boundary.
    path,
    reference,
    state,
    release,
    runner,
    catalog_path,
    *,
    require_packaged,
    references=None,
):
    before = path.read_bytes()
    assessment = matcher.match_code(before, references or [reference])
    assert not assessment.limited
    assert {match["state"] for match in assessment.matches} == {state}
    packaged = packaged_match_evidence(before, reference, state, required=require_packaged)

    result = run_scan(path, "--code-references", catalog_path)
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert any(item["patch_status"] == state + "_code_match" for item in report["findings"])

    main_code, main_report = run_main_scan(path, catalog_path)
    assert main_code == (1 if state == "vulnerable" else 3)
    assert any(item["patch_status"] == state + "_code_match" for item in main_report["findings"])
    assert path.read_bytes() == before
    run_runtime_smoke(path, release, runner)
    return assessment, packaged


@pytest.mark.parametrize(("release", "state"), RELEASES)
@pytest.mark.parametrize("optimization", ["-O2", "-O3"])
@pytest.mark.parametrize("pic", [False, True])
@pytest.mark.skipif(not SOURCE_ROOT, reason="Set BROTLI_TEST_SOURCES for real-build tests")
def test_real_static_decoder(  # noqa: C901, PLR0913, PLR0915, PLR0917 -- End-to-end matrix boundary.
    tmp_path, release, state, optimization, pic, record_property
):
    assert SOURCE_ROOT
    tree = Path(SOURCE_ROOT) / f"brotli-{release}"
    paired_tree = Path(SOURCE_ROOT) / f"brotli-{PAIRED_RELEASE[release]}"
    compiler = shutil.which(os.environ.get("BROTLI_TEST_CC", "cc"))
    archiver = shutil.which(os.environ.get("BROTLI_TEST_AR", "ar"))
    strip = shutil.which(os.environ.get("BROTLI_TEST_STRIP", "strip"))
    assert compiler
    assert archiver
    assert strip
    gc_sections = configured_boolean(
        os.environ.get("BROTLI_TEST_GC_SECTIONS"), "BROTLI_TEST_GC_SECTIONS"
    )
    flags = [optimization, "-fPIC"] if pic else [optimization, "-fno-pic", "-fno-PIE"]
    flags.extend(shlex.split(os.environ.get("BROTLI_TEST_CFLAGS", "")))
    if gc_sections:
        flags.extend(flag for flag in GC_COMPILE_FLAGS if flag not in flags)
    linker_flags = shlex.split(os.environ.get("BROTLI_TEST_LDFLAGS", ""))
    if gc_sections:
        linker_flags.extend(flag for flag in GC_LINK_FLAGS if flag not in linker_flags)
    build = runpy.run_path(str(ROOT / "scripts/build_binary_references.py"))["build_references"]
    catalog = build([tree, paired_tree], compiler, flags)
    references = [matcher.CodeReference.from_json(entry) for entry in catalog["references"]]
    assert {item.metadata["state"] for item in references} == {"fixed", "vulnerable"}
    reference = next(item for item in references if item.metadata["state"] == state)
    catalog_path = tmp_path / "references.json"
    catalog_path.write_text(json.dumps(catalog))
    objects = []
    decode_object = None
    for source in sorted([*(tree / "c/dec").glob("*.c"), *(tree / "c/common").glob("*.c")]):
        obj = tmp_path / (source.parent.name + "-" + source.stem + ".o")
        invoke([compiler, *flags, "-I", str(tree / "c/include"), "-c", str(source), "-o", str(obj)])
        objects.append(str(obj))
        if source.name == "decode.c":
            decode_object = obj
    assert decode_object is not None
    library = tmp_path / "libdecoder.a"
    invoke([archiver, "rcs", str(library), *objects])
    main = tmp_path / "main.c"
    main.write_text(runtime_harness_source(release))
    runner = configured_runner(os.environ.get("BROTLI_TEST_RUNNER"))
    require_packaged = configured_boolean(
        os.environ.get("BROTLI_TEST_REQUIRE_PACKAGED"), "BROTLI_TEST_REQUIRE_PACKAGED"
    )
    record_property("compiler", reference.metadata["compiler"])
    record_property("reference_catalog", str(REFERENCE_CATALOG))
    record_property("flags", reference.metadata["flags"])
    record_property(
        "target_identity",
        f"{reference.metadata['machine']}/"
        f"{profile_value(reference.metadata, 'elf_class')}/"
        f"{profile_value(reference.metadata, 'byteorder')}",
    )
    record_property("runtime_runner", shlex.join(runner) if runner is not None else "disabled")
    record_property("require_packaged", require_packaged)
    record_property("gc_sections", gc_sections)
    record_property("opposite_release", PAIRED_RELEASE[release])
    discarded = (
        defined_function_symbols(decode_object.read_bytes()) & UNRELATED_DECODER_APIS
        if gc_sections
        else set()
    )
    addresses = []
    for link_flag in ("-no-pie", "-pie") if pic else ("-no-pie",):
        variant = link_flag.removeprefix("-")
        normal = tmp_path / ("app" + link_flag + "-normal")
        invoke(
            [
                compiler,
                *flags,
                *linker_flags,
                link_flag,
                "-I",
                str(tree / "c/include"),
                str(main),
                str(library),
                "-o",
                str(normal),
            ]
        )
        normal_assessment, normal_packaged = assert_artifact(
            normal,
            reference,
            state,
            release,
            runner,
            catalog_path,
            require_packaged=require_packaged,
            references=references,
        )
        if gc_sections:
            assert_gc_population(normal, reference, discarded)
        record_property(f"packaged_{variant}_normal", normal_packaged)
        addresses.append(
            file_offset_address(normal.read_bytes(), normal_assessment.matches[0]["file_offset"], 1)
        )

        stripped = tmp_path / ("app" + link_flag + "-stripped")
        shutil.copy2(normal, stripped)
        invoke([strip, str(stripped)])
        stripped_data = stripped.read_bytes()
        stripped_header = matcher.elf_header(stripped_data)
        # Loader-required .dynsym may remain; GNU strip must remove .symtab.
        assert all(
            section[1] != 2 for section in matcher.section_headers(stripped_data, stripped_header)
        )
        _, stripped_packaged = assert_artifact(
            stripped,
            reference,
            state,
            release,
            runner,
            catalog_path,
            require_packaged=require_packaged,
            references=references,
        )
        record_property(f"packaged_{variant}_stripped", stripped_packaged)

        # Removing section headers must not change the answer.
        sectionless_path = tmp_path / ("app" + link_flag + "-sectionless")
        shutil.copy2(stripped, sectionless_path)
        sectionless = bytearray(sectionless_path.read_bytes())
        layout = matcher.ELFLayout.of(matcher.elf_header(bytes(sectionless)))
        small = layout.bits == 32
        struct.pack_into(
            ("<" if layout.byteorder == "little" else ">") + ("I" if small else "Q"),
            sectionless,
            32 if small else 40,
            0,
        )
        sectionless[46 if small else 58 : 52 if small else 64] = bytes(6)
        sectionless_path.write_bytes(sectionless)
        _, sectionless_packaged = assert_artifact(
            sectionless_path,
            reference,
            state,
            release,
            runner,
            catalog_path,
            require_packaged=require_packaged,
            references=references,
        )
        record_property(f"packaged_{variant}_sectionless", sectionless_packaged)

        bundle = tmp_path / "app.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("bin/service", sectionless)
        result = run_scan(bundle, "--code-references", catalog_path)
        assert result.returncode == 1
        finding = json.loads(result.stdout)["findings"][0]
        assert finding["path"].endswith("!bin/service")
        assert finding["patch_status"] == state + "_code_match"
    if gc_sections:
        version_source = tmp_path / "version.c"
        version_source.write_text(version_harness_source(release))
        version_only = tmp_path / "version-only"
        invoke(
            [
                compiler,
                *flags,
                *linker_flags,
                "-pie" if pic else "-no-pie",
                "-I",
                str(tree / "c/include"),
                str(version_source),
                str(library),
                "-o",
                str(version_only),
            ]
        )
        assert_missing_gc_population(
            version_only,
            reference,
            references,
            state,
            catalog_path,
            runner,
            release,
        )
    if pic:
        assert addresses[0] != addresses[1]
    variants = len(addresses) * 3
    record_property("artifact_variants", variants)
    record_property("packaged_checks", variants)
    record_property("missing_role_checks", int(gc_sections))
    record_property("runtime_checks", variants + int(gc_sections) if runner is not None else 0)
