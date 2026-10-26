import subprocess
from types import SimpleNamespace

import pytest
import test_binary_builds as builds
from test_binary_builds import (
    COMPRESSED_PAYLOAD,
    EXPECTED_PLAINTEXT,
    RUNTIME_TIMEOUT_SECONDS,
    configured_boolean,
    configured_runner,
    expected_runtime_output,
    run_runtime_smoke,
    runtime_harness_source,
)


def test_runner_is_explicit_and_uses_shell_quoting_only_for_argv_parsing():
    assert configured_runner(None) is None
    assert configured_runner('/qemu/qemu-mips-static -L "/sys root"') == [
        "/qemu/qemu-mips-static",
        "-L",
        "/sys root",
    ]
    with pytest.raises(ValueError, match="must contain"):
        configured_runner("   ")


def test_packaged_requirement_is_explicit_and_strictly_parsed():
    assert configured_boolean(None, "FLAG") is False
    assert configured_boolean("yes", "FLAG") is True
    assert configured_boolean("0", "FLAG") is False
    with pytest.raises(ValueError, match="FLAG"):
        configured_boolean("sometimes", "FLAG")


def test_harness_embeds_valid_nonempty_payload_and_both_decoder_apis():
    source = runtime_harness_source("1.2.1")
    assert len(COMPRESSED_PAYLOAD) == 36
    assert EXPECTED_PLAINTEXT == b"Brotli cross-architecture smoke\n"
    assert "BrotliDecoderDecompress(" in source
    assert "BrotliDecoderDecompressStream(" in source
    assert "BrotliDecoderVersion()" in source
    assert "UINT32_C(16785409)" in source
    assert expected_runtime_output("1.2.1") == "ok version=1.2.1 bytes=32\n"


def test_absent_runner_never_executes_target(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", pytest.fail)
    run_runtime_smoke(tmp_path / "target", "1.2.1", None)


def test_runtime_smoke_uses_bounded_argv_and_exact_output(tmp_path, monkeypatch):
    target = tmp_path / "target"
    calls = []

    def run(command, **options):
        calls.append((command, options))
        return SimpleNamespace(
            returncode=0,
            stdout=expected_runtime_output("1.2.1"),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", run)
    runner = ["/qemu/qemu-aarch64-static", "-L", "/usr/aarch64-linux-gnu"]
    run_runtime_smoke(target, "1.2.1", runner)
    assert calls == [
        (
            [*runner, str(target)],
            {
                "check": False,
                "capture_output": True,
                "text": True,
                "timeout": RUNTIME_TIMEOUT_SECONDS,
            },
        )
    ]


def test_legacy_packaged_profile_defaults_to_elf64_little_endian(monkeypatch):
    metadata = {
        "compiler": "legacy GCC 16.2.1",
        "machine": 183,
        "flags": "-O2 -fPIC",
        "source_sha256": "a" * 64,
    }
    reference = SimpleNamespace(metadata={**metadata, "elf_class": 64, "byteorder": "little"})
    monkeypatch.setattr(builds, "PACKAGED_REFERENCES", [SimpleNamespace(metadata=metadata)])
    monkeypatch.setattr(
        builds.matcher,
        "match_code",
        lambda *_: builds.matcher.CodeAssessment(
            [
                {
                    **metadata,
                    "state": "fixed",
                }
            ],
            "fixture match",
        ),
    )
    assert builds.packaged_match_evidence(b"fixture", reference, "fixed", required=True) == (
        "exact packaged compiler/profile matched"
    )


def test_packaged_profile_mismatch_is_recorded_or_required(monkeypatch):
    reference = SimpleNamespace(
        metadata={
            "compiler": "custom compiler",
            "machine": 183,
            "elf_class": 64,
            "byteorder": "little",
            "flags": "-O2",
            "source_sha256": "a" * 64,
        }
    )
    monkeypatch.setattr(builds, "PACKAGED_REFERENCES", [])
    monkeypatch.setattr(
        builds.matcher,
        "match_code",
        lambda *_: builds.matcher.CodeAssessment([], "no packaged profile"),
    )
    evidence = builds.packaged_match_evidence(b"fixture", reference, "fixed", required=False)
    assert "outside packaged provenance" in evidence
    assert "same_state_matches=0" in evidence
    with pytest.raises(pytest.fail.Exception, match="REQUIRE_PACKAGED"):
        builds.packaged_match_evidence(b"fixture", reference, "fixed", required=True)


def test_stripped_dynsym_indicators_do_not_invalidate_code_match(tmp_path, monkeypatch):
    target = tmp_path / "stripped-mips"
    target.write_bytes(b"fixture")
    reference = SimpleNamespace(metadata={"state": "fixed"})
    match = {"state": "fixed"}
    monkeypatch.setattr(
        builds.matcher,
        "match_code",
        lambda *_: builds.matcher.CodeAssessment([match], "fixture match"),
    )
    monkeypatch.setattr(builds, "packaged_match_evidence", lambda *_args, **_kwargs: "fixture")
    monkeypatch.setattr(
        builds,
        "run_scan",
        lambda *_: SimpleNamespace(
            returncode=1,
            stdout='{"findings":[{"patch_status":"fixed_code_match",'
            '"code_matches":[{}],"indicators":["BrotliDecoderVersion"]}]}',
        ),
    )
    monkeypatch.setattr(
        builds,
        "run_main_scan",
        lambda *_: (3, {"findings": [{"patch_status": "fixed_code_match"}]}),
    )
    monkeypatch.setattr(builds, "run_runtime_smoke", lambda *_: None)
    assessment, packaged = builds.assert_artifact(
        target,
        reference,
        "fixed",
        "1.2.1",
        None,
        tmp_path / "catalog.json",
        require_packaged=False,
    )
    assert assessment.matches == [match]
    assert packaged == "fixture"


@pytest.mark.parametrize("failure", ["timeout", "nonzero", "output", "stderr"])
def test_runtime_timeout_nonzero_and_output_mismatch_fail(tmp_path, monkeypatch, failure):
    def run(command, **options):
        del options
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, RUNTIME_TIMEOUT_SECONDS)
        return SimpleNamespace(
            returncode=7 if failure == "nonzero" else 0,
            stdout=(
                "wrong\n"
                if failure == "output"
                else expected_runtime_output("1.2.1")
                if failure == "stderr"
                else ""
            ),
            stderr="fixture failure" if failure != "output" else "",
        )

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(AssertionError):
        run_runtime_smoke(tmp_path / "target", "1.2.1", ["/trusted/qemu"])
