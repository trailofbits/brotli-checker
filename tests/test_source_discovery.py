import contextlib
import io
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import brotli_source_discovery as discovery
import pytest
import trailmark
from trailmark.models.annotations import EntrypointKind, EntrypointTag, TrustLevel
from trailmark.models.diagnostics import ParseDiagnostic
from trailmark.models.edges import CodeEdge, EdgeConfidence, EdgeKind
from trailmark.models.graph import CodeGraph
from trailmark.models.nodes import CodeUnit, NodeKind, NodeOrigin, SourceLocation


def unit(node_id, *, proxy=False, attributes=(), line=1):
    return CodeUnit(
        node_id,
        node_id.rsplit(":", 1)[-1],
        NodeKind.PROXY if proxy else NodeKind.FUNCTION,
        SourceLocation("/src/app.c", line, line, 0, 12),
        origin=NodeOrigin.PROXY if proxy else NodeOrigin.SOURCE,
        attributes=attributes,
    )


def call(source, target, line=2, *, confidence=EdgeConfidence.CERTAIN, attributes=()):
    return CodeEdge(
        source,
        target,
        EdgeKind.CALLS,
        confidence,
        SourceLocation("/src/app.c", line, line, 4, 35),
        attributes,
    )


def graph_with(nodes, edges, *, sources=1):
    return CodeGraph(
        nodes={node.id: node for node in nodes},
        edges=edges,
        root_path="/src",
        language="c",
        source_file_counts={"c": sources},
    )


def decoder_graph():
    graph = graph_with(
        [unit("app:main"), unit("app:wrapper"), unit("app:BrotliDecoderDecompress")],
        [call("app:main", "app:wrapper", 8), call("app:wrapper", "app:BrotliDecoderDecompress", 4)],
    )
    graph.entrypoints["app:main"] = EntrypointTag(
        EntrypointKind.USER_INPUT, TrustLevel.TRUSTED_INTERNAL, "main heuristic"
    )
    return graph


def collect(graph, **limits):
    return discovery.discover(graph, "0.7.0", discovery.Limits(**limits))


def run_cli(monkeypatch, graph=None, *arguments):
    monkeypatch.setattr(discovery, "runtime_version", lambda: "0.7.0")
    if graph is not None:
        monkeypatch.setattr(discovery, "load_graph", lambda _root, _language: graph)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = discovery.main(["/src", *arguments])
    return code, json.loads(output.getvalue())


def test_decoder_chain_preserves_calls_spans_ids_counts_and_entrypoint():
    result = collect(decoder_graph())
    assert result["status"] == "evidence_collected"
    assert result["trailmark_version"] == "0.7.0"
    assert result["coverage"] == {
        "language": "c",
        "source_files": 1,
        "source_file_counts": {"c": 1},
        "initial_parsing_bounded": False,
    }
    candidate = result["candidates"][0]
    assert candidate["symbol"] == "BrotliDecoderDecompress"
    assert candidate["call"]["source"] == "app:wrapper"
    assert candidate["call"]["target"] == "app:BrotliDecoderDecompress"
    assert candidate["call"]["location"] == {
        "file_path": "/src/app.c",
        "start_line": 4,
        "end_line": 4,
        "start_col": 4,
        "end_col": 35,
    }
    assert candidate["call"]["resolution"] == "source"
    assert result["neighborhood"]["caller_depths"] == {"app:wrapper": 0, "app:main": 1}
    assert result["neighborhood"]["entrypoints"] == [
        {
            "node_id": "app:main",
            "kind": "user_input",
            "trust_level": "trusted_internal",
            "asset_value": "low",
            "description": "main heuristic",
        }
    ]
    assert {row["index"] for row in result["neighborhood"]["calls"]} == {0, 1}
    assert not any(result["truncation"].values())


def test_repeated_global_fetch_calls_keep_spans_but_shadowed_bindings_do_not_match():
    proxy = unit("proxy:app:fetch", proxy=True, attributes=(("proxy_kind", "unresolved"),))
    local = unit("app:fetch")
    parameter = unit("proxy:binding.fetch", proxy=True, attributes=(("proxy_kind", "unresolved"),))
    graph = graph_with(
        [unit("app:main"), proxy, local, parameter],
        [
            call("app:main", proxy.id, 3),
            call("app:main", proxy.id, 7),
            call("app:main", local.id, 9),
            call("app:main", parameter.id, 10, attributes=(("binding_blocked", True),)),
        ],
    )
    result = collect(graph)
    assert result["candidate_count"] == 2
    assert [row["call"]["location"]["start_line"] for row in result["candidates"]] == [3, 7]
    assert all(row["call"]["resolution"] == "unresolved" for row in result["candidates"])
    assert result["candidates"][0]["call"]["confidence"] == "certain"
    nodes = {row["id"]: row for row in result["neighborhood"]["nodes"]}
    assert nodes[proxy.id]["origin"] == "proxy"
    assert nodes[proxy.id]["attributes"] == {"proxy_kind": "unresolved"}


def test_requested_symbols_add_aliases_and_wrappers_without_inventing_binding():
    alias = unit("proxy:app:download", proxy=True, attributes=(("proxy_kind", "unresolved"),))
    wrapper = unit("app:inflate")
    graph = graph_with(
        [unit("app:main"), alias, wrapper],
        [
            call("app:main", alias.id, attributes=(("raw_target", "app:download"),)),
            call("app:main", wrapper.id),
        ],
    )
    assert collect(graph)["candidate_count"] == 0
    result = discovery.discover(graph, "0.7.0", discovery.Limits(), ("download", "app:inflate"))
    assert [row["symbol"] for row in result["candidates"]] == ["download", "app:inflate"]
    assert result["candidates"][0]["call"]["attributes"] == {"raw_target": "app:download"}
    assert result["candidates"][1]["call"]["resolution"] == "source"
    assert any("ESM import aliases" in row for row in result["limitations"])


@pytest.mark.parametrize(
    "raw",
    [
        "node.zlib:brotliDecompress",
        "brotli.decompress",
        "undici:request",
        "undici.stream",
        "undici:pipeline",
        "globalThis.fetch",
        "zlib.createBrotliDecompress",
        "zlib.brotliDecompressSync",
        "app:BrotliDecoderDecompressStream",
    ],
)
def test_qualified_decoder_and_fetch_calls_are_discovery_candidates(raw):
    target = unit("proxy:" + raw, proxy=True, attributes=(("proxy_kind", "unresolved"),))
    edge = call("app:main", target.id, attributes=(("raw_target", raw),))
    result = collect(graph_with([unit("app:main"), target], [edge]))
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["call"]["attributes"]["raw_target"] == raw


def test_callback_edges_are_kept_with_uncertainty_and_deferred_metadata():
    graph = decoder_graph()
    graph.nodes["app:callback"] = unit("app:callback")
    graph.edges = [
        call(
            "app:main",
            "app:callback",
            confidence=EdgeConfidence.UNCERTAIN,
            attributes=(("deferred", True),),
        ),
        call("app:callback", "app:BrotliDecoderDecompress"),
    ]
    result = collect(graph)
    deferred = next(row for row in result["neighborhood"]["calls"] if row["source"] == "app:main")
    assert deferred["confidence"] == "uncertain"
    assert deferred["attributes"] == {"deferred": True}
    assert result["neighborhood"]["entrypoints"][0]["node_id"] == "app:main"


def test_configured_links_are_distinguishable_from_source_calls():
    target = unit("proxy:external.fetch", proxy=True, attributes=(("proxy_kind", "external"),))
    declared = replace(
        call("app:main", target.id),
        location=None,
        attributes=(("configured_by", ".trailmark/links.toml"),),
    )
    result = collect(graph_with([unit("app:main"), target], [declared]))
    edge = result["candidates"][0]["call"]
    assert edge["location"] is None
    assert edge["resolution"] == "external_or_synthetic"
    assert edge["attributes"]["configured_by"] == ".trailmark/links.toml"
    assert any("entrypoints.toml" in message for message in result["limitations"])


def test_caller_walk_handles_cycles_and_reports_relevant_unresolved_outgoing_calls():
    graph = decoder_graph()
    missing = unit("proxy:other", proxy=True, attributes=(("proxy_kind", "unresolved"),))
    graph.nodes[missing.id] = missing
    graph.edges += [call("app:wrapper", "app:main"), call("app:main", missing.id)]
    result = collect(graph)
    assert result["status"] == "evidence_collected"
    assert result["neighborhood"]["caller_depths"] == {"app:wrapper": 0, "app:main": 1}
    assert len(result["neighborhood"]["calls"]) == 4
    assert (
        next(row for row in result["neighborhood"]["calls"] if row["target"] == missing.id)[
            "resolution"
        ]
        == "unresolved"
    )
    assert not any(result["truncation"].values())


@pytest.mark.parametrize(
    ("limits", "flag"),
    [
        ({"max_call_edges": 1}, "call_edges"),
        ({"max_caller_nodes": 1}, "caller_nodes"),
        ({"max_depth": 0}, "depth"),
    ],
)
def test_each_caller_bound_is_explicit_and_incomplete(limits, flag):
    result = collect(decoder_graph(), **limits)
    assert result["status"] == "incomplete"
    assert result["truncation"][flag] is True
    assert len(result["neighborhood"]["calls"]) <= limits.get("max_call_edges", 256)
    assert len(result["neighborhood"]["caller_depths"]) <= limits.get("max_caller_nodes", 128)


def test_candidate_limit_counts_all_matches_and_limits_output():
    graph = decoder_graph()
    graph.edges.append(call("app:main", "app:BrotliDecoderDecompress", 20))
    result = collect(graph, max_candidates=1)
    assert result["candidate_count"] == 2
    assert len(result["candidates"]) == 1
    assert result["truncation"]["candidates"] is True
    assert result["status"] == "incomplete"
    # Both source calls may appear as caller context despite only one being a selected candidate.
    assert len(result["neighborhood"]["calls"]) <= result["limits"]["max_call_edges"]


def test_candidate_edges_respect_call_limit_and_caller_seed_limit():
    graph = decoder_graph()
    graph.edges += [call("app:main", "app:BrotliDecoderDecompress", 15)]
    result = collect(graph, max_call_edges=1)
    assert result["candidate_count"] == 2
    assert len(result["candidates"]) == 1
    assert result["truncation"]["call_edges"] is True
    result = collect(graph, max_caller_nodes=1)
    assert result["truncation"]["caller_nodes"] is True
    assert len(result["neighborhood"]["caller_depths"]) == 1


def test_diagnostics_are_preserved_bounded_and_counted():
    graph = decoder_graph()
    graph.parse_diagnostics = [
        ParseDiagnostic("c", "c", SourceLocation("/src/a.c", line, line), "syntax_error", "error")
        for line in (3, 7)
    ]
    result = collect(graph, max_diagnostics=1)
    assert result["parse_diagnostic_count"] == 2
    assert result["parse_diagnostics"][0]["location"]["start_line"] == 3
    assert len(result["parse_diagnostics"]) == 1
    assert result["truncation"]["diagnostics"] is True
    assert result["status"] == "incomplete"
    assert {gap["kind"] for gap in result["gaps"]} == {"parse_diagnostics", "bounded_output"}


def test_empty_and_declaration_only_graphs_have_different_collection_status():
    empty = collect(graph_with([], [], sources=0))
    assert empty["status"] == "incomplete"
    assert empty["gaps"][0]["kind"] == "empty_source"
    declarations = collect(graph_with([unit("app:BrotliDecoderDecompress")], []))
    assert declarations["status"] == "evidence_collected"
    assert declarations["candidates"] == []
    assert declarations["neighborhood"]["entrypoints"] == []
    assert any(
        "No graph path does not mean unreachable" in row for row in declarations["limitations"]
    )


def test_noncall_edges_do_not_create_a_source_call_candidate():
    graph = decoder_graph()
    graph.edges = [replace(graph.edges[1], kind=EdgeKind.CONTAINS)]
    assert collect(graph)["candidate_count"] == 0


def test_dangling_call_targets_still_keep_unresolved_evidence():
    graph = graph_with([unit("app:main")], [call("app:main", "BrotliDecoderDecompress")])
    result = collect(graph)
    assert result["candidates"][0]["call"]["resolution"] == "unresolved"
    assert result["neighborhood"]["nodes"][0]["id"] == "app:main"


def test_cli_success_empty_and_bounded_results_have_documented_exit_codes(monkeypatch):
    assert run_cli(monkeypatch, decoder_graph())[0] == 0
    assert run_cli(monkeypatch, graph_with([], [], sources=0))[0] == 3
    code, result = run_cli(monkeypatch, decoder_graph(), "--max-depth", "0")
    assert code == 3
    assert result["truncation"]["depth"] is True


def test_cli_forwards_languages_symbols_and_resolves_root(monkeypatch, tmp_path):
    calls = []
    graph = graph_with([unit("app:main")], [call("app:main", "download")])
    monkeypatch.setattr(discovery, "runtime_version", lambda: "0.7.0")

    def load(root, language):
        calls.append((root, language))
        return graph

    monkeypatch.setattr(discovery, "load_graph", load)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = discovery.main(
            [
                str(tmp_path / ".." / tmp_path.name),
                "--language",
                "javascript",
                "--symbol",
                "download",
                "--symbol",
                "inflate",
            ]
        )
    assert code == 0
    assert calls == [(str(tmp_path.resolve()), "javascript")]
    assert json.loads(output.getvalue())["candidates"][0]["symbol"] == "download"


@pytest.mark.parametrize(
    "failure", [ValueError("collision"), OSError("unreadable"), RecursionError("deep")]
)
def test_parser_failures_emit_incomplete_json_and_keep_known_runtime_version(monkeypatch, failure):
    def fail(_root, _language):
        raise failure

    monkeypatch.setattr(discovery, "load_graph", fail)
    code, result = run_cli(monkeypatch)
    assert code == 3
    assert result["trailmark_version"] == "0.7.0"
    assert result["coverage"]["source_files"] is None
    assert result["gaps"] == [{"kind": "discovery_error", "message": str(failure)}]


def test_missing_runtime_emits_json_without_attempting_to_parse(monkeypatch):
    monkeypatch.setitem(sys.modules, "trailmark", None)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        code = discovery.main(["/src"])
    result = json.loads(output.getvalue())
    assert code == 3
    assert result["status"] == "incomplete"
    assert result["trailmark_version"] is None
    assert "trailmark" in result["gaps"][0]["message"]


@pytest.mark.parametrize("failure", [RuntimeError("Symlink loop"), OSError("Cannot resolve path")])
def test_root_resolution_failure_keeps_json_and_supplied_root(monkeypatch, failure):
    def fail(_path):
        raise failure

    monkeypatch.setattr(Path, "resolve", fail)
    code, result = run_cli(monkeypatch)
    assert code == 3
    assert result["root"] == "/src"
    assert result["gaps"] == [{"kind": "discovery_error", "message": str(failure)}]


def test_old_runtime_fails_explicitly(monkeypatch):
    monkeypatch.setattr(trailmark, "__version__", "0.6.9")
    with pytest.raises(ValueError, match=r"Trailmark >=0\.7"):
        discovery.runtime_version()


def test_runtime_version_is_reported_without_loading_a_grammar():
    assert discovery.runtime_version() == trailmark.__version__


def test_public_parse_api_and_entrypoint_detection_are_called_without_strict_mode(monkeypatch):
    graph = graph_with([unit("app:serve")], [])
    graph.entrypoints["app:existing"] = EntrypointTag(EntrypointKind.API)
    observations = []
    parser_module = ModuleType("trailmark.parse")
    entry_module = ModuleType("trailmark.analysis.entrypoints")

    def parse(root, **kwargs):
        observations.append((root, kwargs))
        return graph

    def entrypoints(parsed, root):
        assert parsed is graph
        assert root == "/src"
        return {"app:serve": EntrypointTag(EntrypointKind.API)}

    monkeypatch.setattr(parser_module, "parse_directory", parse, raising=False)
    monkeypatch.setattr(entry_module, "detect_entrypoints", entrypoints, raising=False)
    monkeypatch.setitem(sys.modules, "trailmark.parse", parser_module)
    monkeypatch.setitem(sys.modules, "trailmark.analysis.entrypoints", entry_module)
    assert discovery.load_graph("/src", "c,javascript") is graph
    assert observations == [
        ("/src", {"language": "c,javascript", "allow_empty": True, "strict": False})
    ]
    assert set(graph.entrypoints) == {"app:existing", "app:serve"}


@pytest.mark.parametrize(
    "arguments",
    [
        ["--max-depth", "-1"],
        ["--max-candidates", "0"],
        ["--max-caller-nodes", "-1"],
        ["--max-call-edges", "0"],
        ["--max-diagnostics", "0"],
        ["--symbol", " "],
        ["--unknown"],
        ["--max-depth", "bad"],
    ],
)
def test_cli_misuse_exits_two(arguments):
    with pytest.raises(SystemExit) as error:
        discovery.main(["/src", *arguments])
    assert error.value.code == 2


PARSER_TESTS = pytest.mark.skipif(
    os.environ.get("BROTLI_TRAILMARK_TESTS") != "1",
    reason="Real parser fixtures require explicit BROTLI_TRAILMARK_TESTS=1",
)


@PARSER_TESTS
def test_real_c_parser_finds_decoder_chain_and_main(tmp_path):
    (tmp_path / "app.c").write_text(
        "int BrotliDecoderDecompress(int x) { return x; }\n"
        "int wrapper(int x) { return BrotliDecoderDecompress(x); }\n"
        "int main() { return wrapper(0); }\n"
    )
    result = collect(discovery.load_graph(str(tmp_path), "c"))
    assert result["candidate_count"] == 1
    assert result["candidates"][0]["call"]["location"]["start_line"] == 2
    assert result["neighborhood"]["caller_depths"] == {"app:wrapper": 0, "app:main": 1}
    assert result["neighborhood"]["entrypoints"][0]["node_id"] == "app:main"
    assert result["coverage"]["source_file_counts"] == {"c": 1}


@PARSER_TESTS
def test_real_js_parser_preserves_global_shadowing_aliases_callbacks_and_blind_spot(tmp_path):
    source = (
        "import { fetch as download } from 'undici';\n"
        "async function globalCall(url) {\n fetch(url);\n return fetch(url);\n}\n"
        "function localCall(url) { function fetch(x) { return x; } return fetch(url); }\n"
        "function parameterCall(fetch) { return fetch(url); }\n"
        "function aliasCall(url) { return download(url); }\n"
        "function main() { emitter.on('data', d => zlib.brotliDecompress(d)); }\n"
        "fetch('top-level');\n"
    )
    (tmp_path / "app.js").write_text(source)
    graph = discovery.load_graph(str(tmp_path), "javascript")
    result = collect(graph)
    assert result["candidate_count"] == 3
    assert [
        row["call"]["location"]["start_line"]
        for row in result["candidates"]
        if row["symbol"] == "fetch"
    ] == [3, 4]
    assert not any(
        "localCall" in row["call"]["source"] or "parameterCall" in row["call"]["source"]
        for row in result["candidates"]
    )
    assert any(row["attributes"].get("deferred") for row in result["neighborhood"]["calls"])
    aliases = discovery.discover(graph, "0.7.0", discovery.Limits(), ("download",))
    assert aliases["candidate_count"] == 4
    assert not any(row["call"]["location"]["start_line"] == 10 for row in aliases["candidates"])
    assert result["parse_diagnostics"] == []


@PARSER_TESTS
def test_real_commonjs_renaming_typescript_and_parse_error(tmp_path):
    (tmp_path / "app.js").write_text(
        "const {brotliDecompress: decode} = require('node:zlib');\n"
        "function main() { return decode(input); }\n"
    )
    result = collect(discovery.load_graph(str(tmp_path), "javascript"))
    edge = result["candidates"][0]["call"]
    assert edge["attributes"]["import_binding"] is True
    assert edge["attributes"]["raw_target"] == "node.zlib:brotliDecompress"
    (tmp_path / "client.ts").write_text(
        "async function request(url: string) { return fetch(url); }\n"
    )
    result = collect(discovery.load_graph(str(tmp_path), "typescript"))
    assert result["candidate_count"] == 1
    assert result["coverage"]["source_file_counts"] == {"typescript": 1}
    (tmp_path / "bad.c").write_text("int main( { BROKEN\n")
    result = collect(discovery.load_graph(str(tmp_path), "c"))
    assert result["status"] == "incomplete"
    assert result["parse_diagnostic_count"] > 0


@PARSER_TESTS
def test_real_empty_directory_and_configured_entrypoint(tmp_path):
    assert collect(discovery.load_graph(str(tmp_path), "auto"))["status"] == "incomplete"
    (tmp_path / "app.c").write_text(
        "int BrotliDecoderDecompress(int x) { return x; }\n"
        "int serve() { return BrotliDecoderDecompress(0); }\n"
    )
    settings = tmp_path / ".trailmark"
    settings.mkdir()
    (settings / "entrypoints.toml").write_text(
        '[[entrypoint]]\nnode = "app:serve"\nkind = "api"\n'
        'trust = "untrusted_external"\ndescription = "Configured fixture"\n'
    )
    result = collect(discovery.load_graph(str(tmp_path), "c"))
    assert result["neighborhood"]["entrypoints"][0]["description"] == "Configured fixture"
