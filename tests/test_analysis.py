import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from brotli_analysis import MAX_ANALYSIS_GAPS, AnalysisSession, scan_with_analysis
from brotli_binary_data import sha256_data
from test_binary_match import elf, reference, write_catalog
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
