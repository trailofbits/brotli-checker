import contextlib
import hashlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts/brotli_inventory.py"
spec = importlib.util.spec_from_file_location("inventory", SCRIPT)
if spec is None or spec.loader is None:
    message = f"Cannot load the inventory helper at {SCRIPT}"
    raise ImportError(message)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


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
        result = inventory.Inventory(self.registry, **defaults)
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
        assert "Vulnerable Brotli source found: /app/component" in rendered
        assert len(report["findings"]) == 2

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
