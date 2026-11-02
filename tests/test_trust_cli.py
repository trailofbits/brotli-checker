import hashlib
import json

import pytest
from test_binary_match import reference, write_catalog
from test_flirt_integration import run_main
from test_jsf import b64url, fixture


def test_cli_authenticates_jsf_without_promoting_bom_claim(tmp_path):
    jcs = pytest.importorskip("rfc8785")
    target = tmp_path / "application"
    target.write_bytes(b"unknown application")
    document, policy, private = fixture()
    document["components"][0]["hashes"][0]["content"] = hashlib.sha256(
        target.read_bytes()
    ).hexdigest()
    del document["signature"]["value"]
    document["signature"]["value"] = b64url(private.sign(jcs.dumps(document)))
    packet, trust = tmp_path / "signed.json", tmp_path / "policy.json"
    packet.write_text(json.dumps(document))
    trust.write_text(json.dumps(policy))
    references = write_catalog(tmp_path, [reference(salt=b"unused")])
    status, output, error = run_main(
        target,
        "--jsf",
        packet,
        "--jsf-policy",
        trust,
        "--code-references",
        references,
        "--no-flirt",
        "--json",
    )
    assert not error
    assert status == 3
    report = json.loads(output)
    evidence = report["authenticated_provenance"][0]
    assert evidence["signature_status"] == "verified"
    assert evidence["patch_status"] == "unknown"
    assert evidence["bound_artifacts"] == [report["artifacts"][0]["id"]]
    assert {"jsf_document", "jsf_policy"} <= {
        feed["category"] for feed in report["evidence_envelope"]["feeds"]
    }
    document["components"][0]["hashes"][0]["content"] = "a" * 64
    packet.write_text(json.dumps(document))
    _, output, error = run_main(
        target,
        "--jsf",
        packet,
        "--jsf-policy",
        trust,
        "--code-references",
        references,
        "--no-flirt",
        "--json",
    )
    assert not error
    tampered = json.loads(output)
    assert not tampered["authenticated_provenance"]
    assert any("JSF unverified" in gap["reason"] for gap in tampered["coverage"]["gaps"])
