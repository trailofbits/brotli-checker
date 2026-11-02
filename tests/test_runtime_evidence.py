import copy
import hashlib
import json

import brotli_runtime_evidence as subject
import pytest
from brotli_attestations import CapturedDocument
from test_binary_match import reference, write_catalog
from test_flirt_integration import run_main


def fixture():
    artifacts = [
        {"id": "app", "namespace": "deployment:/image", "logical_path": "/app", "sha256": "a" * 64},
        {
            "id": "decoder",
            "namespace": "deployment:/image",
            "logical_path": "/decoder.so",
            "sha256": "b" * 64,
        },
    ]
    trace = {
        "schema_version": 1,
        "deployment": {
            "id": "production/pod-1/process-12/start-2",
            "namespace": "deployment:/image",
            "configuration_sha256": "c" * 64,
        },
        "collector": "reviewed-collector/v1",
        "events": [
            {
                "kind": "symbol_binding",
                "source": {"logical_path": "/app", "sha256": "a" * 64},
                "target": {"logical_path": "/decoder.so", "sha256": "b" * 64},
                "symbol": "BrotliDecoderDecompressStream",
                "observed_at": "2026-11-02T12:00:00Z",
            }
        ],
    }
    return trace, artifacts


@pytest.mark.parametrize("kind", ["symbol_binding", "decoder_call"])
def test_exact_runtime_join_preserves_evidence_boundaries(kind):
    trace, artifacts = fixture()
    trace["events"][0]["kind"] = kind
    before = copy.deepcopy(artifacts)
    result = subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)
    assert result["events"][0]["source"] == "app"
    assert result["events"][0]["target"] == "decoder"
    assert result["events"][0]["kind"] == kind
    assert result["events"][0]["attacker_control"] == "unknown"
    assert result["events"][0]["authentication"] == "not_independently_verified"
    assert result["patch_status"] == "unknown"
    assert result["absence_proven"] is False
    assert artifacts == before


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sha256", "d" * 64),
        ("logical_path", "/other"),
        ("sha256", "B" * 64),
        ("sha256", "g" * 64),
        ("logical_path", ""),
    ],
)
def test_no_digest_or_path_fallback(field, value):
    trace, artifacts = fixture()
    trace["events"][0]["target"][field] = value
    with pytest.raises(ValueError, match=r"Runtime|runtime"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


@pytest.mark.parametrize(
    "namespace", ["deployment:/other", "unresolved:image", "unresolved-image:a"]
)
def test_same_bytes_in_another_namespace_do_not_bind(namespace):
    trace, artifacts = fixture()
    trace["deployment"]["namespace"] = namespace
    with pytest.raises(ValueError, match=r"Runtime|runtime"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


def test_duplicate_artifact_is_ambiguous():
    trace, artifacts = fixture()
    artifacts.append(dict(artifacts[-1], id="other"))
    with pytest.raises(ValueError, match="one exact"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


@pytest.mark.parametrize("kind", ["loaded", "not_reachable", "fixed", [], None])
def test_load_and_negative_claims_are_not_call_observations(kind):
    trace, artifacts = fixture()
    trace["events"][0]["kind"] = kind
    with pytest.raises(ValueError, match=r"Runtime|runtime"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


@pytest.mark.parametrize("when", ["2026-11-02", "2026-11-02T12:00:00", "yesterday", "", 0])
def test_observation_requires_dated_timezone(when):
    trace, artifacts = fixture()
    trace["events"][0]["observed_at"] = when
    with pytest.raises(ValueError, match=r"Runtime|runtime"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


@pytest.mark.parametrize("events", [[], None, {}, [None]])
def test_invalid_population(events):
    trace, artifacts = fixture()
    trace["events"] = events
    with pytest.raises(ValueError, match=r"Runtime|runtime"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


def test_event_limit_and_unknown_fields(monkeypatch):
    trace, artifacts = fixture()
    monkeypatch.setattr(subject, "MAX_RUNTIME_EVENTS", 1)
    trace["events"] *= 2
    with pytest.raises(ValueError, match="over limit"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)
    trace["events"] = trace["events"][:1]
    trace["fixed"] = True
    with pytest.raises(ValueError, match="unsupported fields"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


@pytest.mark.parametrize("version", [True, 0, 2, "1"])
def test_schema_is_strict(version):
    trace, artifacts = fixture()
    trace["schema_version"] = version
    with pytest.raises(ValueError, match="schema"):
        subject.bind_runtime_trace(json.dumps(trace).encode(), artifacts)


def test_invalid_trace_is_gap_not_partial_success():
    trace, artifacts = fixture()
    trace["events"].append(
        dict(trace["events"][0], target={"logical_path": "/wrong", "sha256": "b" * 64})
    )
    document = CapturedDocument("trace", json.dumps(trace).encode())
    results, gaps = subject.inspect_runtime_traces([document], artifacts)
    assert not results
    assert len(gaps) == 1
    assert gaps[0]["path"] == "trace"


def test_valid_and_invalid_documents_independent_and_hashed(monkeypatch):
    trace, artifacts = fixture()
    raw = json.dumps(trace).encode()
    documents = [CapturedDocument("ok", raw), CapturedDocument("bad", b"{}")]
    results, gaps = subject.inspect_runtime_traces(documents, artifacts)
    assert len(results) == len(gaps) == 1
    assert results[0]["sha256"] == hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(subject, "MAX_RUNTIME_TRACES", 1)
    with pytest.raises(ValueError, match="count"):
        subject.inspect_runtime_traces(documents, artifacts)


def test_cli_trace_bound_to_captured_feed_without_patch_promotion(tmp_path):
    root = tmp_path / "image"
    root.mkdir()
    app, decoder = root / "app", root / "decoder.so"
    app.write_bytes(b"app bytes")
    decoder.write_bytes(b"decoder bytes")
    trace, _ = fixture()
    trace["deployment"]["namespace"] = "deployment:" + str(root)
    trace["events"][0]["source"]["sha256"] = hashlib.sha256(app.read_bytes()).hexdigest()
    trace["events"][0]["target"]["sha256"] = hashlib.sha256(decoder.read_bytes()).hexdigest()
    packet = tmp_path / "trace.json"
    packet.write_text(json.dumps(trace))
    references = write_catalog(tmp_path, [reference(salt=b"unused")])
    status, output, error = run_main(
        "--deployment-root",
        root,
        "--runtime-trace",
        packet,
        "--code-references",
        references,
        "--no-flirt",
        "--json",
    )
    assert not error
    assert status == 3
    report = json.loads(output)
    assert report["runtime_observations"][0]["patch_status"] == "unknown"
    assert report["runtime_observations"][0]["events"][0]["target"] in {
        artifact["id"] for artifact in report["artifacts"] if artifact["path"] == str(decoder)
    }
    assert "runtime-trace" in {feed["category"] for feed in report["evidence_envelope"]["feeds"]}
