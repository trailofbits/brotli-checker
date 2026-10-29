import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import brotli_analysis as analysis
import pytest
from brotli_analysis import MAX_ANALYSIS_GAPS, AnalysisSession, scan_with_analysis
from brotli_binary_data import sha256_data
from brotli_debug_companions import SuppliedCompanion
from brotli_inventory import Inventory
from brotli_package_provenance import load_vendor_snapshot
from test_binary_match import elf, reference, write_catalog
from test_debug_companions import elf_note, elf_section_note, pdb, pe_rsds
from test_flirt_integration import run_main


def record(session, data, path, depth=0):
    return session.record(data, path, sha256_data(data), depth)


def test_sbom_hash_binding_never_promotes_patch_state():
    session = AnalysisSession([Path("/supplied")], xrefs=False)
    target = record(session, b"application", "/supplied/application")
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "brotli",
                "version": "1.2.1",
                "bom-ref": "decoder",
                "hashes": [{"alg": "SHA-256", "content": target["sha256"]}],
            }
        ],
    }
    record(session, json.dumps(document).encode(), "/supplied/bom.json")
    result = session.finish()
    assert result["relations"] == [
        {
            "source": result["artifacts"][1]["id"],
            "component": "decoder",
            "target": target["id"],
            "kind": "artifact_hash_bound",
        }
    ]
    assert all("patch_status" not in item for item in result["artifacts"])


def test_archive_namespaces_are_isolated_and_traversal_is_unresolved():
    session = AnalysisSession([Path("/supplied")], xrefs=False)
    first = record(session, b"archive-one", "/supplied/one.tar")
    second = record(session, b"archive-two", "/supplied/two.tar")
    a = record(session, b"library", "/supplied/one.tar!lib/decoder.so", 1)
    b = record(session, b"library", "/supplied/two.tar!lib/decoder.so", 1)
    escaped = record(session, b"library", "/supplied/one.tar!../../host", 1)
    assert a["namespace"] == first["id"]
    assert b["namespace"] == second["id"]
    assert a["namespace"] != b["namespace"]
    assert escaped["namespace"].startswith("unresolved:")
    assert escaped["deployment_root"] is False
    assert "_hashes" not in escaped
    assert session.gaps


def test_rollback_removes_nested_evidence_and_metadata_budget():
    session = AnalysisSession([Path("/supplied")])
    record(session, b"prior", "/supplied/prior")
    checkpoint = session.checkpoint()
    record(session, b"broken-json", "/supplied/bom.json")
    record(session, b"child", "/supplied/bom.json!child", 1)
    assert session.gaps
    assert session.metadata_bytes
    session.rollback(checkpoint)
    assert len(session.artifacts) == 1
    assert session.gaps == []
    assert session.gap_count == 0
    assert session.metadata_bytes == 0


def test_deployment_metadata_cannot_own_another_root():
    root = Path("/image")
    session = AnalysisSession([root, Path("/host")], deployment_roots=[root], xrefs=False)
    status = (
        b"Package: brotli\nStatus: install ok installed\nVersion: 1.2.1\nArchitecture: amd64\n\n"
    )
    record(session, status, "/image/var/lib/dpkg/status")
    record(session, b"/usr/lib/decoder.so\n", "/image/var/lib/dpkg/info/brotli.list")
    digest = hashlib.md5(b"library", usedforsecurity=False).hexdigest()
    record(
        session,
        f"{digest}  usr/lib/decoder.so\n".encode(),
        "/image/var/lib/dpkg/info/brotli.md5sums",
    )
    local = record(session, b"library", "/image/usr/lib/decoder.so")
    host = record(session, b"library", "/host/usr/lib/decoder.so")
    result = session.finish()
    assert [item["artifact"] for item in result["ownership"]] == [local["id"]]
    assert host["namespace"] != local["namespace"]
    assert result["ownership"][0]["matches"][0]["evidence_strength"] == "package_file_hash_match"


def test_function_graph_is_attached_without_patch_promotion():
    session = AnalysisSession([Path("/supplied")])
    data = elf(bytes.fromhex("c0035fd6"))
    record(session, data, "/supplied/decoder")
    result = session.enrich(
        data, "/supplied/decoder", {"detection_status": "decoder_tables_detected"}
    )
    assert "function_graph" in result
    assert "patch_status" not in result


def test_cli_explicit_sidecar_is_parsed_without_scanning_cwd(tmp_path):
    sidecar = tmp_path / "unusual-name.json"
    sidecar.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [{"type": "library", "name": "brotli", "bom-ref": "decoder"}],
            }
        )
    )
    references = write_catalog(tmp_path, [reference(salt=b"unused")])
    _, output, error = run_main("--sbom", sidecar, "--code-references", references, "--json")
    assert error == ""
    report = json.loads(output)
    assert report["scope"] == [str(sidecar)]
    assert len(report["artifacts"]) == 1
    assert report["artifacts"][0]["provenance"]["components"][0]["name"] == "brotli"
    assert report["flirt_configuration"]["status"] == "not_applicable"


def test_invalid_vendor_snapshot_is_input_error(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"ordinary")
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text('{"vendor": "debian"}')
    references = write_catalog(tmp_path, [reference(salt=b"unused")])
    status, output, error = run_main(
        target, "--vendor-snapshot", snapshot, "--code-references", references, "--json"
    )
    assert status == 2
    assert output == ""
    assert "Invalid analysis input" in error


def test_analysis_gap_retention_is_bounded_and_rollback_restores_exact_count():
    session = AnalysisSession([Path("/supplied")], xrefs=False)
    checkpoint = session.checkpoint()
    for index in range(MAX_ANALYSIS_GAPS + 7):
        session.gap(f"path-{index}", "gap")
    result = session.finish()
    assert len(result["gaps"]) == MAX_ANALYSIS_GAPS
    assert result["gap_details_omitted"] == 7
    assert session.gap_count == MAX_ANALYSIS_GAPS + 7
    session.rollback(checkpoint)
    assert session.gap_count == 0
    assert session.gaps == []


def test_scan_propagates_omitted_analysis_gap_count_exactly(tmp_path):
    class FakeInventory:
        def __init__(self):
            self.analysis: AnalysisSession | None = None
            self.gap_count = 0
            self.gaps = []

        def gap(self, path, reason):
            self.gap_count += 1
            self.gaps.append({"path": path, "reason": reason})

        def scan_roots(self, _roots):
            assert self.analysis is not None
            for index in range(MAX_ANALYSIS_GAPS + 7):
                self.analysis.gap(f"path-{index}", "gap")

    inventory = FakeInventory()
    args = SimpleNamespace(
        debug_file=[],
        vendor_snapshot=[],
        deployment_root=[],
        no_xrefs=True,
        sbom=[],
    )
    result = scan_with_analysis(cast("Any", inventory), [tmp_path], cast("Any", args))
    assert inventory.gap_count == MAX_ANALYSIS_GAPS + 7
    assert len(inventory.gaps) == MAX_ANALYSIS_GAPS
    assert result["gap_details_omitted"] == 7


def test_virtual_oci_images_have_distinct_namespaces_and_retained_history():
    session = AnalysisSession([Path("/supplied")], xrefs=False)
    parent = record(session, b"oci-archive", "/supplied/images.tar")
    first = session.register_image(
        "/supplied/images.tar!image[0]",
        parent["path"],
        0,
        "sha256:first",
        ({"layer": "one", "action": "add_or_replace", "path": "usr/lib/a.so"},),
    )
    second = session.register_image(
        "/supplied/images.tar!image[1]",
        parent["path"],
        0,
        "sha256:second",
        ({"layer": "two", "action": "whiteout", "path": "usr/lib/a.so"},),
    )
    first_member = record(session, b"first", "/supplied/images.tar!image[0]!usr/lib/a.so", 1)
    second_member = record(session, b"second", "/supplied/images.tar!image[1]!usr/lib/a.so", 1)
    assert first["id"] != second["id"]
    assert first_member["namespace"] == first["id"]
    assert second_member["namespace"] == second["id"]
    assert first_member["logical_path"] == second_member["logical_path"] == "/usr/lib/a.so"
    result = session.finish()
    assert [image["manifest"] for image in result["images"]] == [
        "sha256:first",
        "sha256:second",
    ]
    assert result["images"][1]["history"][0]["action"] == "whiteout"


def test_image_registration_and_members_rollback_together():
    session = AnalysisSession([Path("/supplied")], xrefs=False)
    parent = record(session, b"oci-archive", "/supplied/images.tar")
    checkpoint = session.checkpoint()
    session.register_image(
        "/supplied/images.tar!image[0]",
        parent["path"],
        0,
        "sha256:first",
        ({"action": "add_or_replace"},),
    )
    record(session, b"member", "/supplied/images.tar!image[0]!etc/os-release", 1)
    session.rollback(checkpoint)
    assert session.images == []
    assert session.image_history_count == 0
    assert len(session.artifacts) == 1
    unresolved = record(session, b"later", "/supplied/images.tar!image[0]!etc/os-release", 1)
    assert unresolved["namespace"] == parent["id"]


@pytest.mark.parametrize("member", ["../host", "/etc/os-release", "etc\\os-release"])
def test_unsafe_image_members_never_acquire_deployment_scope(member):
    session = AnalysisSession([Path("/supplied")], xrefs=False)
    record(session, b"archive", "/supplied/image.tar")
    session.register_image("/supplied/image.tar!image[0]", "/supplied/image.tar", 0, "manifest", ())
    item = record(session, b"ID=host", "/supplied/image.tar!image[0]!" + member, 1)
    assert item["namespace"].startswith("unresolved:")
    assert item["deployment_root"] is False
    assert "_metadata" not in item
    assert "_hashes" not in item
    assert any("unsafe" in gap["reason"] for gap in session.gaps)


def test_unprovided_parent_does_not_create_deployment_or_hash_ownership():
    session = AnalysisSession([Path("/supplied")])
    item = record(session, b"ID=host", "/missing.tar!etc/os-release", 1)
    assert item["deployment_root"] is False
    assert item["namespace"].startswith("unresolved:")
    assert "_hashes" not in item
    assert session.enrich(b"data", "/not-recorded", {}) == {}
    image = session.register_image("missing!image", "missing", 0, "manifest", ())
    assert image["parent"] is None
    assert image["id"].startswith("unresolved-image:")
    assert any("parent artifact" in gap["reason"] for gap in session.gaps)


def test_nested_deployment_root_owns_its_metadata_not_the_outer_root():
    session = AnalysisSession(
        [Path("/images")], deployment_roots=[Path("/images"), Path("/images/child")]
    )
    item = record(session, b"ID=debian", "/images/child/etc/os-release")
    assert item["namespace"] == "deployment:/images/child"
    assert item["logical_path"] == "/etc/os-release"
    assert item["_metadata"] == b"ID=debian"
    ordinary = record(session, b"ID=host", "/etc/os-release")
    assert ordinary["deployment_root"] is False
    assert "_metadata" not in ordinary


def test_image_history_budget_is_cumulative_not_per_image(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_IMAGE_HISTORY", 2)
    session = AnalysisSession([Path("/supplied")])
    record(session, b"archive", "/supplied/image.tar")
    history = ({"path": "first"}, {"path": "second"})
    first = session.register_image(
        "/supplied/image.tar!one", "/supplied/image.tar", 0, "one", history
    )
    second = session.register_image(
        "/supplied/image.tar!two", "/supplied/image.tar", 0, "two", history
    )
    assert len(first["history"]) == 2
    assert first["history_omitted"] == 0
    assert second["history"] == ()
    assert second["history_omitted"] == 2
    assert session.image_history_count == 2
    assert any("history retention" in gap["reason"] for gap in session.gaps)


def test_metadata_budget_accepts_exact_limit_and_rejects_cumulative_overflow(monkeypatch):
    raw = b'{"bomFormat":"CycloneDX","specVersion":"1.6"}'
    monkeypatch.setattr(analysis, "MAX_METADATA_BYTES", len(raw))
    session = AnalysisSession([Path("/supplied")])
    first = record(session, raw, "/supplied/first.cdx.json")
    second = record(session, raw, "/supplied/second.cdx.json")
    assert "provenance" in first
    assert "provenance" not in second
    assert session.metadata_bytes == len(raw)
    assert any("cumulative byte budget" in gap["reason"] for gap in session.gaps)
    irrelevant = record(session, b"x", "/supplied/unrelated.md5sums")
    assert "_metadata" not in irrelevant


@pytest.mark.parametrize("count", [2, 3])
def test_sbom_relation_limit_retains_exact_complete_prefix(monkeypatch, count):
    monkeypatch.setattr(analysis, "MAX_RELATIONS", 2)
    session = AnalysisSession([Path("/supplied")])
    targets = [record(session, b"same", f"/supplied/copy-{index}") for index in range(count)]
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "brotli",
                "type": "library",
                "bom-ref": "decoder",
                "hashes": [{"alg": "SHA-256", "content": targets[0]["sha256"]}],
            }
        ],
    }
    record(session, json.dumps(document).encode(), "/supplied/bom.json")
    result = session.finish()
    assert [edge["target"] for edge in result["relations"]] == [item["id"] for item in targets[:2]]
    assert any("Relationship budget" in gap["reason"] for gap in result["gaps"]) == (count > 2)


@pytest.mark.parametrize(
    ("vendor", "release", "matches"),
    [("debian", "13", True), ("ubuntu", "13", False), ("debian", "12", False)],
)
def test_vendor_assertion_requires_both_same_root_os_fields(vendor, release, matches):
    snapshot = load_vendor_snapshot(
        json.dumps(
            {
                "schema_version": 1,
                "snapshot_date": "2026-10-28",
                "vendor": "debian",
                "release": "13",
                "assertions": [
                    {
                        "package": "libbrotli1",
                        "fixed_version": "1.2.1-1",
                        "advisory_url": "https://vendor.example/advisory",
                    }
                ],
            }
        )
    )
    session = AnalysisSession(
        [Path("/image")], deployment_roots=[Path("/image")], snapshots=(snapshot,)
    )
    record(
        session,
        (
            b"Package: libbrotli1\nStatus: install ok installed\n"
            b"Version: 1.2.1-1\nArchitecture: amd64\n\n"
        ),
        "/image/var/lib/dpkg/status",
    )
    record(
        session,
        f'#ID=forged\n#comment\nID={vendor}\nVERSION_ID="{release}"\n'.encode(),
        "/image/etc/os-release",
    )
    result = session.finish()
    assert bool(result["vendor_assertions"]) is matches
    if matches:
        assert result["vendor_assertions"][0]["patch_status"] == "unknown"
        assert result["vendor_assertions"][0]["status"] == "meets_vendor_fixed_version"
    else:
        assert any("does not match" in gap["reason"] for gap in result["gaps"])


@pytest.mark.parametrize("extra_byte", [False, True])
def test_vendor_snapshot_read_limit_is_inclusive_and_detects_extra_byte(
    tmp_path, monkeypatch, extra_byte
):
    raw = json.dumps(
        {
            "schema_version": 1,
            "snapshot_date": "2026-10-28",
            "vendor": "debian",
            "release": "13",
            "assertions": [],
        }
    ).encode()
    monkeypatch.setattr(analysis, "MAX_METADATA_BYTES", len(raw))
    path = tmp_path / "snapshot.json"
    path.write_bytes(raw + (b" " if extra_byte else b""))
    inventory = Inventory({"fingerprints": []}, None, None, 10, 0)
    args = argparse.Namespace(
        debug_file=[], vendor_snapshot=[path], deployment_root=[], no_xrefs=True, sbom=[]
    )
    if extra_byte:
        with pytest.raises(ValueError, match="snapshot exceeds metadata byte budget"):
            scan_with_analysis(inventory, [], args)
    else:
        result = scan_with_analysis(inventory, [], args)
        assert result["analysis_configuration"]["vendor_snapshots"] == [str(path)]
        assert inventory.gap_count == 0


@pytest.mark.parametrize(
    "path", ["/image/unrelated.md5sums", "/image/var/lib/dpkg/info/not-a-record"]
)
def test_unrelated_deployment_files_do_not_consume_package_metadata_budget(path):
    session = AnalysisSession([Path("/image")], deployment_roots=[Path("/image")])
    item = record(session, b"unrelated", path)
    assert "_metadata" not in item
    assert session.metadata_bytes == 0


@pytest.mark.parametrize("kind", ["elf", "pe"])
def test_supplied_debug_evidence_is_routed_for_both_native_layouts(kind):
    if kind == "elf":
        artifact = elf_note(b"identity")
        companion = SuppliedCompanion("app.debug", elf_section_note(b"identity"))
    else:
        guid = bytes(range(16))
        artifact = pe_rsds(guid, 7)
        companion = SuppliedCompanion("app.pdb", pdb(guid, 7))
    session = AnalysisSession([Path("/supplied")], xrefs=False, companions=(companion,))
    record(session, artifact, "/supplied/app")
    result = session.enrich(artifact, "/supplied/app", {"detection_status": "not_detected"})
    assert result["debug_companions"]["status"] == "verified"
    assert result["debug_companions"]["matches"][0]["patch_status"] == "unknown"
    assert "function_graph" not in result
