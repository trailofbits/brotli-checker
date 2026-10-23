import bz2
import contextlib
import gzip
import hashlib
import io
import json
import lzma
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import brotli_inventory as inventory
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts/brotli_inventory.py"


def tar_bytes(name, content):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


class TestInventory:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path: Path) -> None:
        self.root = tmp_path
        self.sample = b"a complete file used as an exact-match fixture\n"
        self.registry = {
            "fingerprints": [
                {
                    "sha256": hashlib.sha256(self.sample).hexdigest(),
                    "git_blob": "fixture",
                    "state": "vulnerable",
                    "sources": [],
                }
            ]
        }

    def scan(self, path=None, **limits):
        defaults = {
            "max_file_bytes": 1024 * 1024,
            "max_total_bytes": 4 * 1024 * 1024,
            "max_files": 100,
            "archive_depth": 2,
        }
        defaults.update(limits)
        result = inventory.Inventory(
            self.registry,
            defaults["max_file_bytes"],
            defaults["max_total_bytes"],
            defaults["max_files"],
            defaults["archive_depth"],
        )
        result.scan_root(path or self.root)
        return result

    def run_cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = inventory.main([*map(str, args), "--json"])
        return code, json.loads(output.getvalue())

    def test_version_boundaries_and_backport_uncertainty(self):
        for old, fixed in (("1.0.9", "1.0.10"), ("1.1.0", "1.1.1"), ("1.2.0", "1.2.1")):
            assert (
                inventory.assess_version("brotli", old)["patch_status"] == "potentially_vulnerable"
            )
            assert (
                inventory.assess_version("brotli", fixed)["patch_status"]
                == "upstream_fixed_version"
            )
        for old, fixed in (
            ("22.23.3", "22.23.4"),
            ("24.22.0", "24.22.1"),
            ("26.12.0", "26.12.1"),
        ):
            assert inventory.assess_version("node", old)["patch_status"] == "potentially_vulnerable"
            assert (
                inventory.assess_version("node", fixed)["patch_status"] == "upstream_fixed_version"
            )
        for component, version in (
            ("brotli", "1.0.9-2+deb12u2"),
            ("brotli", "1.2.1rc1"),
            ("brotli", "2.0.0"),
            ("brotli", "1.0.2"),
            ("node", "20.99.99"),
        ):
            assert inventory.assess_version(component, version)["patch_status"] == "unknown"

    def test_exact_copy_found_under_unrelated_name_in_hidden_dependency_tree(self):
        target = self.root / ".build/node_modules/pkg/payload.dat"
        target.parent.mkdir(parents=True)
        target.write_bytes(self.sample)
        result = self.scan()
        assert len(result.findings) == 1
        assert result.findings[0]["patch_status"] == "vulnerable_source"
        assert result.findings[0]["reachability"] == "unknown"
        assert result.findings[0]["shipment"] == "unknown"

    def test_each_copy_survives_mixed_fixed_and_vulnerable_results(self):
        fixed = b"separate fixed-file fixture\n"
        self.registry["fingerprints"].append(
            {
                "sha256": hashlib.sha256(fixed).hexdigest(),
                "git_blob": "fixed-fixture",
                "state": "fixed",
                "sources": [],
            }
        )
        (self.root / "old.c").write_bytes(self.sample)
        (self.root / "new.c").write_bytes(fixed)
        assert {row["patch_status"] for row in self.scan().findings} == {
            "vulnerable_source",
            "fixed_source",
        }

    def test_nested_jar_and_native_library_are_candidates_not_exploitable(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr("native/libbrotli.so", b"\x7fELF\0BrotliDecoderDecompressStream\0")
            archive.writestr("source/unrelated.dat", self.sample)
        with zipfile.ZipFile(self.root / "app.war", "w") as archive:
            archive.writestr("WEB-INF/lib/provider.jar", inner.getvalue())
        result = self.scan()
        assert any(
            row["patch_status"] == "vulnerable_source" and ".jar!source" in row["path"]
            for row in result.findings
        )
        native = [row for row in result.findings if row["path"].endswith("libbrotli.so")]
        assert native
        assert all(
            row["patch_status"] == "unknown" and row["exploitability"] == "not_assessed"
            for row in native
        )

    def test_tar_members_are_read_without_extraction(self):
        target = self.root / "package.tar.gz"
        with tarfile.open(target, "w:gz") as archive:
            info = tarfile.TarInfo("../../outside.c")
            info.size = len(self.sample)
            archive.addfile(info, io.BytesIO(self.sample))
        result = self.scan()
        assert result.findings[0]["patch_status"] == "vulnerable_source"
        assert list(self.root.iterdir()) == [target]

    def test_archive_depth_and_expansion_limits_are_visible(self):
        target = self.root / "package.zip"
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("large", b"0" * 100000)
        result = self.scan(max_file_bytes=1024)
        assert result.files_read == 1
        assert result.gap_count == 1
        result = self.scan(archive_depth=0)
        assert result.archives_opened == 0
        assert result.gap_count == 1

    def test_compressed_tar_expansion_is_bounded(self):
        target = self.root / "package.tar.gz"
        with tarfile.open(target, "w:gz") as archive:
            info = tarfile.TarInfo("large")
            info.size = 100000
            archive.addfile(info, io.BytesIO(b"0" * info.size))
        result = self.scan(max_file_bytes=1024)
        assert result.bytes_read < 2048
        assert result.gap_count == 1

    def test_symlinks_are_not_followed_and_git_is_excluded(self):
        (self.root / "link.c").symlink_to(SCRIPT)
        (self.root / "directory").symlink_to(SCRIPT.parent, target_is_directory=True)
        (self.root / ".git").mkdir()
        (self.root / ".git/ignored.c").write_bytes(self.sample)
        result = self.scan()
        assert result.files_read == 0
        assert result.gap_count == 2

    def test_corrupt_archive_and_missing_root_do_not_look_clean(self):
        (self.root / "bad.jar").write_bytes(b"not a ZIP")
        code, result = self.run_cli(self.root)
        assert code == 3
        assert result["coverage"]["gap_count"] > 0
        code, result = self.run_cli(self.root / "missing")
        assert code == 3
        assert result["coverage"]["gap_count"] > 0

    def test_no_matches_and_unknown_metadata_are_not_clean(self):
        code, result = self.run_cli(self.root)
        assert code == 3
        assert result["findings"] == []
        (self.root / "pom.xml").write_text("<artifactId>brotli4j</artifactId>")
        code, result = self.run_cli(self.root)
        assert code == 3
        assert result["findings"][0]["patch_status"] == "unknown"

    def test_cli_version_exit_codes_and_result_scope(self):
        code, result = self.run_cli("--brotli-version", "1.1.1")
        assert code == 0
        assert result["findings"][0]["reachability"] == "unknown"
        assert result["scope"] == []
        code, result = self.run_cli("--node-version", "24.22.0")
        assert code == 1
        assert result["result"] == "affected_evidence_found"
        code, result = self.run_cli("--brotli-version", "1.0.9-vendor-fix")
        assert code == 3

    def test_byte_budget_and_count_gaps(self):
        for name in ("a", "b", "c"):
            (self.root / name).write_bytes(self.sample)
        result = self.scan(max_files=1)
        assert len(result.findings) == 1
        assert result.gap_count > 0
        result = self.scan(max_total_bytes=len(self.sample))
        assert len(result.findings) == 1
        assert result.gap_count > 0

    def test_plain_report_preserves_vulnerable_copy_and_hides_internal_statuses(self):
        _, report = self.run_cli(self.root)
        report["findings"] = [
            inventory.finding("/app/fixed.c", "exact_source_match", "fixed_source", "fixture"),
            inventory.finding("/app/old.c", "exact_source_match", "vulnerable_source", "fixture"),
        ]
        report["user_summary"] = inventory.summarize(report)
        assert report["user_summary"]["status"] == "needs_attention"
        rendered = inventory.render_text(report)
        assert "/app/fixed.c" in rendered
        assert "/app/old.c" in rendered
        assert rendered.index("/app/old.c") < rendered.index("/app/fixed.c")
        assert "vulnerable_source" not in rendered
        assert "fixed_source" not in rendered
        assert report["findings"][1]["reachability"] == "unknown"

    def test_unchecked_files_prevent_a_fixed_summary(self):
        _, report = self.run_cli(self.root)
        assert report["user_summary"]["status"] == "needs_more_information"
        assert report["user_summary"]["next_steps"]
        report["findings"] = [
            inventory.finding("/app/fixed.c", "exact_source_match", "fixed_source", "fixture")
        ]
        report["coverage"]["gap_count"] = 1
        report["coverage"]["gaps"] = [{"path": "/app/skipped.jar", "reason": "fixture limit"}]
        report["user_summary"] = inventory.summarize(report)
        assert report["user_summary"]["status"] == "needs_more_information"
        assert "/app/skipped.jar" in inventory.render_text(report)

    def test_version_report_includes_the_specific_update_and_running_app_check(self):
        code, report = self.run_cli("--node-version", "24.22.0")
        assert code == 1
        assert report["user_summary"]["status"] == "needs_attention"
        rendered = inventory.render_text(report)
        assert "24.22.1" in rendered
        assert "Node.js 24.22.0" in rendered
        assert "running app" in rendered
        assert "supplied:node:" not in rendered

    def test_multiple_evidence_items_become_one_display_row_without_hiding_warning(
        self,
    ):
        _, report = self.run_cli(self.root)
        report["findings"] = [
            inventory.finding("/app/component", "artifact_name_candidate", "unknown", "fixture"),
            inventory.finding(
                "/app/component", "exact_source_match", "vulnerable_source", "fixture"
            ),
        ]
        report["user_summary"] = inventory.summarize(report)
        rendered = inventory.render_text(report)
        assert rendered.count("/app/component") == 1
        assert 'Vulnerable Brotli source found: "/app/component"' in rendered
        assert len(report["findings"]) == 2

    def test_extensionless_image_layer_does_not_disappear_behind_a_fixed_version(self):
        target = self.root / "image.tar"
        layer = tar_bytes("usr/lib/libbrotlidec.so.1.0.9", b"\x7fELF\0stripped fixture")
        target.write_bytes(tar_bytes("blobs/sha256/abcdef", layer))
        code, report = self.run_cli(target, "--brotli-version", "1.1.1")
        assert code == 3
        assert report["coverage"]["archives_opened"] == 2
        assert any(
            row["path"].endswith("!blobs/sha256/abcdef!usr/lib/libbrotlidec.so.1.0.9")
            and row["patch_status"] == "unknown"
            for row in report["findings"]
        )
        limited, report = self.run_cli(target, "--brotli-version", "1.1.1", "--archive-depth", "1")
        assert limited == 3
        assert report["coverage"]["gap_count"] > 0

    @pytest.mark.parametrize(
        "compress", [lambda data: data, gzip.compress, bz2.compress, lzma.compress]
    )
    def test_renamed_nested_tar_contents_are_classified(self, compress):
        target = self.root / "payload.data"
        target.write_bytes(compress(tar_bytes("renamed.c", self.sample)))
        result = self.scan(target)
        assert result.gap_count == 0
        assert any(row["patch_status"] == "vulnerable_source" for row in result.findings)
        assert list(self.root.iterdir()) == [target]

    def test_old_tar_header_without_ustar_magic_is_detected(self):
        content = bytearray(tar_bytes("decoder.c", self.sample))
        content[257:265] = b"\0" * 8
        content[148:156] = b" " * 8
        content[148:156] = f"{sum(content[:512]):06o}\0 ".encode()
        (self.root / "opaque").write_bytes(content)
        assert self.scan().findings[0]["patch_status"] == "vulnerable_source"

    def test_renamed_zip_and_zip_with_executable_prefix_are_opened(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("decoder.c", self.sample)
        for prefix in (b"", b"MZ executable fixture\0"):
            target = self.root / "payload"
            target.write_bytes(prefix + stream.getvalue())
            result = self.scan()
            assert result.findings[0]["patch_status"] == "vulnerable_source"
            assert result.gap_count == 0

    @pytest.mark.parametrize("compress", [gzip.compress, bz2.compress, lzma.compress])
    def test_single_compressed_streams_are_checked_and_bounded(self, compress):
        target = self.root / "opaque"
        target.write_bytes(compress(self.sample))
        assert self.scan().findings[0]["patch_status"] == "vulnerable_source"
        target.write_bytes(compress(b"0" * 100000))
        result = self.scan(max_file_bytes=1024)
        assert result.gap_count == 1
        assert result.bytes_read < 2048

    @pytest.mark.parametrize(
        "signature",
        [
            b"!<arch>\n",
            b"!<thin>\n",
            b"\xed\xab\xee\xdb",
            b"\x28\xb5\x2f\xfd",
            b"7z\xbc\xaf\x27\x1c",
            b"Rar!\x1a\x07",
            b"\x04\x22\x4d\x18",
            b"LZIP",
            b"\x1f\x9d",
            b"MSCF",
            b"xar!",
            b"070701",
            b"\x50\x2a\x4d\x18",
        ],
    )
    def test_unsupported_container_magic_prevents_exit_zero(self, signature):
        target = self.root / "renamed"
        target.write_bytes(signature + b"\0fixture")
        code, report = self.run_cli(target, "--brotli-version", "1.1.1")
        assert code == 3
        assert report["coverage"]["gap_count"] == 1
        assert "Unsupported" in report["coverage"]["gaps"][0]["reason"]

    @pytest.mark.parametrize("suffix", [".deb", ".rpm", ".tar.zst", ".br", ".lzma", ".7z"])
    def test_unsupported_named_packages_prevent_exit_zero(self, suffix):
        target = self.root / ("package" + suffix)
        target.write_bytes(b"opaque content")
        code, report = self.run_cli(target, "--brotli-version", "1.1.1")
        assert code == 3
        assert report["coverage"]["gap_count"] == 1

    @pytest.mark.parametrize(
        "name",
        [
            "libbrotli\x1b[2J\nFAKE.so",
            "libbrotli\udcff.so",
            "libbrotli\u202e.so",
            'libbrotli"\\\r.so',
        ],
    )
    def test_hostile_archive_names_are_safe_in_strict_text_output(self, name):
        target = self.root / "hostile.tar"
        target.write_bytes(tar_bytes(name, b"\0BrotliDecoderDecompress"))
        result = subprocess.run(  # noqa: S603 -- Executes only the checked-in scanner.
            [sys.executable, str(SCRIPT), str(target)],
            capture_output=True,
            check=False,
            env={**os.environ, "PYTHONIOENCODING": "utf-8:strict"},
        )
        assert result.returncode == 3, result.stderr
        output = result.stdout.decode("ascii")
        assert "\x1b" not in output
        assert "\r" not in output
        assert json.dumps(name, ensure_ascii=True)[1:-1] in output
        assert not result.stderr

    def test_hostile_gap_paths_reasons_and_supplied_versions_are_escaped(self):
        target = self.root / "bad\x1b[2J\n.jar"
        target.write_bytes(b"broken")
        _, report = self.run_cli(target, "--node-version", "bad\x1b[2J\nversion")
        output = inventory.render_text(report)
        assert "\x1b" not in output
        assert "\\u001b" in output
        assert "supplied:node:" not in output
        assert "bad\\u001b[2J\\nversion" in output

    def test_in_tree_symlink_targets_are_checked_directly(self):
        real = self.root / "deps"
        real.mkdir()
        (real / "decoder.c").write_bytes(self.sample)
        (self.root / "decoder.c").symlink_to(real / "decoder.c")
        (self.root / "alias").symlink_to(real, target_is_directory=True)
        result = self.scan()
        assert result.gap_count == 0
        assert result.covered_symlinks == 2
        assert len(result.findings) == 1

    def test_broken_and_excluded_symlink_targets_still_prevent_exit_zero(self):
        hidden = self.root / ".git"
        hidden.mkdir()
        (hidden / "decoder.c").write_bytes(self.sample)
        (self.root / "excluded").symlink_to(hidden)
        (self.root / "broken").symlink_to(self.root / "missing")
        code, report = self.run_cli(self.root, "--brotli-version", "1.1.1")
        assert code == 3
        assert report["coverage"]["gap_count"] == 2
        assert report["coverage"]["symlink_targets_checked_directly"] == 0

    @pytest.mark.parametrize("reverse", [False, True])
    def test_symlinks_to_another_supplied_root_are_covered_in_either_order(self, reverse):
        app = self.root / "app"
        app.mkdir()
        shared = self.root / "shared"
        shared.write_text("unrelated content")
        (app / "alias").symlink_to(shared)
        roots = [app, shared]
        code, report = self.run_cli(
            *(reversed(roots) if reverse else roots), "--brotli-version", "1.1.1"
        )
        assert code == 0
        assert report["coverage"]["gap_count"] == 0
        assert report["coverage"]["symlink_targets_checked_directly"] == 1

    def test_python_descriptions_and_cached_strings_do_not_imply_native_dependencies(self):
        metadata = self.root / "pyproject.toml"
        metadata.write_text('[project]\ndescription = "A Brotli security checker"\n')
        cached_source = self.root / "cache_fixture.py"
        cached_source.write_text("BrotliDecoderDecompress = None\n")
        py_compile.compile(str(cached_source), cfile=str(self.root / "cached.pyc"), doraise=True)
        _, report = self.run_cli(self.root)
        assert not report["findings"]
        metadata.write_text('[project]\ndependencies = ["brotli>=1"]\n')
        _, report = self.run_cli(self.root)
        assert report["findings"][0]["kind"] == "dependency_candidate"
        assert report["findings"][0]["evidence"]["matches"][0]["field"] == "project.dependencies"
        output = inventory.render_text(report)
        assert "Dependency or metadata mention" in output
        assert "inside this component" not in output

    def test_native_binary_renamed_pyc_still_produces_a_decoder_lead(self):
        (self.root / "renamed.pyc").write_bytes(b"\x7fELF\0BrotliDecoderDecompress")
        result = self.scan()
        assert result.findings[0]["kind"] == "decoder_symbol_candidate"

    @pytest.mark.parametrize("version", ["20.9.0", "21.0.0", "23.0.0", "25.0.0"])
    def test_eol_node_has_upgrade_advice_without_claiming_decoder_identity(self, version):
        code, report = self.run_cli("--node-version", version)
        assert code == 3
        item = report["findings"][0]
        assert item["patch_status"] == "unknown"
        assert item["reachability"] == "unknown"
        output = inventory.render_text(report)
        assert "end of life" in output
        assert f"Node.js {version}" in output
        assert all(fixed in output for fixed in ("22.23.4", "24.22.1", "26.12.1"))
        assert "supplied:node:" not in output

    def test_help_describes_limits_and_defaults(self, capsys):
        with pytest.raises(SystemExit) as stopped:
            inventory.main(["--help"])
        assert stopped.value.code == 0
        output = capsys.readouterr().out
        for text in ("16 MiB", "256 MiB", "50000", "default: 2", "0 disables"):
            assert text in output

    def test_skill_copy_runs_outside_the_repository(self):
        installed = self.root / "installed/brotli-checker"
        shutil.copytree(SCRIPT.parent.parent, installed)
        elsewhere = self.root / "another-project"
        elsewhere.mkdir()
        result = subprocess.run(  # noqa: S603 -- Runs only the checked-in helper with fixed arguments.
            [
                sys.executable,
                str(installed / "scripts/brotli_inventory.py"),
                "--brotli-version",
                "1.1.1",
                "--json",
            ],
            cwd=elsewhere,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["findings"][0]["patch_status"] == "upstream_fixed_version"
        assert report["findings"][0]["reachability"] == "unknown"

    def test_packaged_fingerprints_have_unique_identity_and_retrievable_sources(self):
        registry = json.loads(inventory.REGISTRY.read_text(encoding="utf-8"))
        entries = registry["fingerprints"]
        assert registry["cve"] == "CVE-2026-111497"
        assert len({entry["sha256"] for entry in entries}) == len(entries)
        assert len({entry["git_blob"] for entry in entries}) == len(entries)
        assert {entry["state"] for entry in entries} == {"vulnerable", "fixed"}
        for entry in entries:
            assert re.search(r"^[0-9a-f]{64}$", entry["sha256"])
            assert re.search(r"^[0-9a-f]{40}$", entry["git_blob"])
            assert entry["size"] > 0
            assert entry["sources"]
            for source in entry["sources"]:
                assert source["url"].startswith("https://raw.githubusercontent.com/")

    @pytest.mark.parametrize("suffix", sorted(inventory.JS_SUFFIXES))
    def test_fetch_without_brotli_dependency_requires_runtime_review(self, suffix):
        (self.root / f"app{suffix}").write_text(
            "// no decoder import or dependency\nconst response = await fetch(userURL);\n"
        )
        (self.root / "package.json").write_text('{"dependencies": {}}')
        code, report = self.run_cli(self.root)
        assert code == 3
        assert len(report["findings"]) == 1
        item = report["findings"][0]
        assert item["kind"] == "node_fetch_candidate"
        assert item["patch_status"] == "unknown"
        assert item["reachability"] == "unknown"
        assert item["exploitability"] == "not_assessed"
        match = item["evidence"]["matches"][0]
        assert (match["line"], match["column"]) == (2, 24)
        assert report["user_summary"]["title"] == "Check the runtime used for fetch responses"
        output = inventory.render_text(report)
        assert "Node.js build" in output
        assert "--node-version" in output
        assert "redirects" in output
        assert "node_fetch_candidate" not in output

    @pytest.mark.parametrize(
        ("source", "signal"),
        [
            ("globalThis.fetch(url)", "fetch_reference"),
            ("global.fetch?.(url)", "fetch_reference"),
            ('globalThis["fetch"](url)', "global_fetch_property"),
            ("global [ 'fetch' ] (url)", "global_fetch_property"),
            ("const get = fetch; get(url);", "fetch_reference"),
            ("const { fetch: get } = globalThis; get(url);", "fetch_reference"),
            ("const get = globalThis['fetch']; get(url);", "global_fetch_property"),
            ("import { fetch as get } from 'undici'; get(url);", "undici_import"),
            ("const { request: get } = require('undici'); get(url);", "undici_import"),
            ("const client = await import('undici'); client.request(url);", "undici_import"),
            ("import * as client from 'undici'; client.request(url);", "undici_import"),
            ("import 'undici/register';", "undici_import"),
            ("const text = \x60result: \x24{await fetch(url)}\x60;", "fetch_reference"),
        ],
    )
    def test_fetch_and_undici_reference_forms(self, source, signal):
        (self.root / "app.js").write_text(source)
        findings = self.scan().findings
        assert len(findings) == 1
        assert findings[0]["patch_status"] == "unknown"
        assert signal in {row["signal"] for row in findings[0]["evidence"]["matches"]}

    def test_comments_strings_and_non_javascript_mentions_are_ignored(self):
        (self.root / "app.js").write_text(
            "// fetch(url); require('undici');\n"
            "/* globalThis['fetch'](url) */\n"
            'const docs = "fetch(userURL)";\n'
            "const example = 'import client from \"undici\"';\n"
            'const label = "fetch"; const packageName = "undici";\n'
            'const url = "https://example.invalid/fetch";\n'
            "const unrelated = prefetch(url); fetcher(url); $fetch(url);\n"
        )
        (self.root / "notes.md").write_text("fetch(userURL)")
        (self.root / "data.json").write_text('{"example": "fetch(userURL)"}')
        assert not self.scan().findings

    def test_comments_between_tokens_preserve_positions(self):
        (self.root / "app.ts").write_text(
            "/* fetch(fake)\nmore comment */\n"
            "const client = require /* explanatory comment */ ('undici');\n"
            "globalThis /* wrapper */ [ 'fetch' ](url);\n"
        )
        item = self.scan().findings[0]
        assert [row["line"] for row in item["evidence"]["matches"]] == [3, 4]
        assert [row["column"] for row in item["evidence"]["matches"]] == [16, 1]

    @pytest.mark.parametrize(
        "source",
        [
            "function fetch(url) { return mockResponse; }",
            "window.fetch(url);",
            "const docs = \x60fetch(url) example only\x60;",
        ],
    )
    def test_custom_browser_or_template_references_never_prove_vulnerability(self, source):
        (self.root / "app.js").write_text(source)
        code, report = self.run_cli(self.root)
        assert code == 3
        assert report["findings"][0]["patch_status"] == "unknown"
        assert report["findings"][0]["reachability"] == "unknown"
        assert "custom implementation" in inventory.render_text(report)

    @pytest.mark.parametrize(
        ("name", "text"),
        [
            ("package.json", '{"dependencies":{"undici":"^6.0.0"}}'),
            ("package-lock.json", '{"node_modules/undici":{"version":"6.0.0"}}'),
            ("pnpm-lock.yaml", "  undici@6.0.0:\n    resolution: {}\n"),
            ("yarn.lock", "undici@^6.0.0:\n  version 6.0.0\n"),
        ],
    )
    def test_undici_dependency_has_node_runtime_advice(self, name, text):
        (self.root / name).write_text(text)
        code, report = self.run_cli(self.root)
        assert code == 3
        item = report["findings"][0]
        assert item["kind"] == "dependency_candidate"
        assert item["evidence"]["possible_node_http_client"] is True
        assert "actual Node.js runtime" in inventory.render_text(report)

    def test_undici_types_alone_do_not_imply_a_runtime_http_client(self):
        (self.root / "package.json").write_text('{"devDependencies":{"undici-types":"^6"}}')
        (self.root / "app.ts").write_text("import type { Dispatcher } from 'undici-types';")
        assert not self.scan().findings

    def test_fetch_source_inside_nested_archives_is_found_without_execution(self):
        marker = self.root / "should-not-exist"
        source = f"require('node:fs').writeFileSync({json.dumps(str(marker))}, 'bad'); fetch(url);"
        with zipfile.ZipFile(self.root / "app.zip", "w") as archive:
            archive.writestr("layer", tar_bytes("app/server.cjs", source.encode()))
        result = self.scan()
        assert result.findings[0]["path"].endswith("app.zip!layer!app/server.cjs")
        assert result.findings[0]["kind"] == "node_fetch_candidate"
        assert not marker.exists()
        assert result.gap_count == 0

    @pytest.mark.parametrize(
        ("flag", "version", "expected"),
        [
            ("--brotli-version", "1.1.1", 3),
            ("--node-version", "24.22.1", 3),
            ("--node-version", "24.22.0", 1),
        ],
    )
    def test_supplied_versions_do_not_clear_unresolved_fetch_runtime(self, flag, version, expected):
        (self.root / "app.js").write_text("fetch(userURL)")
        code, report = self.run_cli(self.root, flag, version)
        assert code == expected
        leads = [item for item in report["findings"] if item["kind"] == "node_fetch_candidate"]
        assert len(leads) == 1
        assert leads[0]["patch_status"] == "unknown"
        assert leads[0]["reachability"] == "unknown"
        assert "adding a Brotli npm package" in inventory.render_text(report)

    def test_fetch_evidence_is_bounded_with_line_positions_and_truncation(self):
        path = self.root / "minified.mjs"
        path.write_text("/* heading\n */\n" + "fetch(url); " * 50)
        item = self.scan().findings[0]
        evidence = item["evidence"]
        assert len(evidence["matches"]) == inventory.MAX_SOURCE_MATCHES
        assert evidence["matches_truncated"] is True
        assert all(row["line"] == 3 for row in evidence["matches"])
        assert all(len(row["text"]) <= 300 for row in evidence["matches"])
        assert [row["column"] for row in evidence["matches"][:3]] == [1, 13, 25]
        path.write_text("fetch(url);\n\nfetch(otherURL);")
        evidence = self.scan().findings[0]["evidence"]
        assert [row["line"] for row in evidence["matches"]] == [1, 3]
        assert evidence["matches_truncated"] is False

    @pytest.mark.parametrize("count", [200, 202])
    def test_gap_details_distinguish_retained_and_omitted_records(self, count):
        for index in range(count):
            (self.root / f"missing-{index:03d}").symlink_to("absent")
        code, report = self.run_cli(self.root)
        assert code == 3
        coverage = report["coverage"]
        assert coverage["gap_count"] == count
        assert len(coverage["gaps"]) == inventory.MAX_RECORDED_GAPS
        assert coverage["gap_details_retained"] == inventory.MAX_RECORDED_GAPS
        assert coverage["gap_details_omitted"] == count - inventory.MAX_RECORDED_GAPS
        output = inventory.render_text(report)
        assert "195 more recorded gap details are available with --json" in output
        if count > inventory.MAX_RECORDED_GAPS:
            assert "2 additional gaps have no retained details" in output
            assert "197 more" not in output
        else:
            assert "no retained details" not in output

    @pytest.mark.parametrize(
        ("component", "version", "explanation"),
        [
            ("node", "20.99.99", "end of life"),
            ("node", "28.0.0", "No upstream patch rule for this Node branch"),
            ("node", "24.22.1-rc1", "Not an unambiguous upstream stable version"),
            ("brotli", "1.2.0-vendor1", "Not an unambiguous upstream stable version"),
            ("brotli", "2.0.0", "Outside snapshot patch rules"),
        ],
    )
    def test_unknown_supplied_versions_keep_identity_and_specific_advice(
        self, component, version, explanation
    ):
        code, report = self.run_cli(f"--{component}-version", version)
        assert code == 3
        item = report["findings"][0]
        assert item["patch_status"] == "unknown"
        assert item["evidence"]["component"] == component
        assert item["evidence"]["supplied_version"] == version
        output = inventory.render_text(report)
        assert version in output
        assert ("Node.js" if component == "node" else "Brotli") in output
        assert f"supplied:{component}:" not in output
        assert explanation in output
        assert "vendor" in output or "embedded Brotli" in output

    def stored_nested_archive(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("native/libbrotli.so", b"\x7fELF\0BrotliDecoderDecompressStream\0")
        target = self.root / "app.war"
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("WEB-INF/lib/provider.jar", stream.getvalue())
        return target

    def test_fully_scanned_containers_do_not_duplicate_leaf_decoder_candidates(self):
        target = self.stored_nested_archive()
        code, report = self.run_cli(target)
        assert code == 3
        assert len(report["findings"]) == 2
        assert {row["kind"] for row in report["findings"]} == {
            "artifact_name_candidate",
            "binary_candidate",
        }
        assert all(
            row["path"].endswith("provider.jar!native/libbrotli.so") for row in report["findings"]
        )
        output = inventory.render_text(report)
        assert len([line for line in output.splitlines() if line.startswith("- Possible")]) == 1
        assert "Containers needing inspection" not in output

    @pytest.mark.parametrize(
        "limits",
        [
            ("--archive-depth", "0"),
            ("--archive-depth", "1"),
            ("--max-files", "2"),
        ],
    )
    def test_unresolved_container_markers_survive_depth_and_budget_limits(self, limits):
        target = self.stored_nested_archive()
        code, report = self.run_cli(target, *limits)
        assert code == 3
        assert report["coverage"]["gap_count"] > 0
        findings = report["findings"]
        assert findings
        assert all(row["kind"] == "container_symbol_candidate" for row in findings)
        assert all(row["patch_status"] == "unknown" for row in findings)
        assert all(row["evidence"]["evidence_scope"] == "container" for row in findings)
        output = inventory.render_text(report)
        assert "Containers needing inspection" in output
        assert "as another decoder copy" in output
        assert "Files and versions checked" not in output

    @pytest.mark.parametrize(
        ("name", "data"),
        [
            ("corrupt.jar", b"not an archive"),
            ("corrupt.tar", b"not an archive"),
            ("corrupt.gz", b"\x1f\x8bnot a gzip stream"),
        ],
    )
    def test_corrupt_container_does_not_count_as_successfully_opened(self, name, data):
        (self.root / name).write_bytes(data)
        code, report = self.run_cli(self.root)
        assert code == 3
        assert report["coverage"]["archives_attempted"] == 1
        assert report["coverage"]["archives_opened"] == 0
        assert report["coverage"]["gap_count"] == 1

    def test_open_archive_with_bad_member_keeps_successful_open_and_container_clue(self):
        stream = io.BytesIO()
        payload = b"\x7fELF\0BrotliDecoderDecompressStream\0"
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("native/decoder.so", payload)
        data = bytearray(stream.getvalue())
        # Corrupt only the stored member body, preserving the central directory.
        data[data.index(payload)] ^= 1
        (self.root / "bad-member.zip").write_bytes(data)
        code, report = self.run_cli(self.root)
        assert code == 3
        assert report["coverage"]["archives_attempted"] == 1
        assert report["coverage"]["archives_opened"] == 1
        assert report["coverage"]["gap_count"] == 1
        assert report["findings"][0]["kind"] == "container_symbol_candidate"
        assert "CRC" in report["coverage"]["gaps"][0]["reason"]

    def test_compressed_tar_counts_as_one_archive_attempt_and_open(self):
        (self.root / "layer.tar.gz").write_bytes(gzip.compress(tar_bytes("data", b"plain text")))
        _, report = self.run_cli(self.root)
        assert report["coverage"]["archives_attempted"] == 1
        assert report["coverage"]["archives_opened"] == 1
        assert report["coverage"]["gap_count"] == 0
