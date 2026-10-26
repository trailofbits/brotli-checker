#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12,<3.16"
# dependencies = ["trailmark==0.7.0"]
# ///
"""Collect Trailmark source-call evidence for an agent's Brotli investigation."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trailmark.models.edges import CodeEdge
    from trailmark.models.graph import CodeGraph
    from trailmark.models.nodes import CodeUnit

DECODER_SYMBOLS = frozenset(
    {
        "BrotliDecoderDecompress",
        "BrotliDecoderDecompressStream",
        "brotliDecompress",
        "brotliDecompressSync",
        "createBrotliDecompress",
        "BrotliInputStream",
        "BrotliStream",
        "BrotliDecoder",
        "BrotliDecompress",
        "brotli_decompress",
        "brotli_uncompress",
    }
)
LIMITATIONS = [
    (
        "Source-call evidence does not establish build selection, runtime reachability, "
        "patch status, or exploitability. No graph path does not mean unreachable."
    ),
    "Bounds limit reported evidence and caller traversal, not initial source parsing or indexing.",
    (
        "Trailmark does not model every call; top-level JavaScript/TypeScript calls may be absent "
        "without a diagnostic."
    ),
    (
        "ESM import aliases and dynamic dispatch may remain unresolved. Use --symbol to add "
        "reviewed aliases or wrappers; no import binding is invented by this helper."
    ),
    (
        "Directory parsing skips vendor, node_modules, build, dist, dot-directories and common "
        "environment/cache directories; directory symlinks are not followed. "
        "File symlinks may be read."
    ),
    (
        "Entrypoints are heuristic or repository configured. Missing entrypoint tags do not prove "
        "that a function is unused. .trailmark/entrypoints.toml override tags are repository "
        "declarations, not proof of runtime exposure."
    ),
    (
        "Edge confidence describes static inference. Deferred callback edges do not establish "
        "callback execution; fetch names do not identify Node.js or its actual runtime version."
    ),
    (
        "Repository .trailmark/links.toml edges are declarations, not extracted source callsites. "
        "Empty parse diagnostics do not establish complete source coverage."
    ),
]


@dataclass(frozen=True)
class Limits:
    max_candidates: int = 32
    max_caller_nodes: int = 128
    max_call_edges: int = 256
    max_depth: int = 6
    max_diagnostics: int = 100


def node_row(node: CodeUnit) -> dict:
    return {
        "id": node.id,
        "name": node.name,
        "kind": node.kind.value,
        "origin": node.origin.value,
        "location": asdict(node.location),
        "attributes": dict(node.attributes),
    }


def edge_row(index: int, edge: CodeEdge, graph: CodeGraph) -> dict:
    target = graph.nodes.get(edge.target_id)
    attributes = dict(target.attributes) if target is not None else {}
    return {
        "index": index,
        "source": edge.source_id,
        "target": edge.target_id,
        "kind": edge.kind.value,
        "confidence": edge.confidence.value,
        "location": asdict(edge.location) if edge.location is not None else None,
        "attributes": dict(edge.attributes),
        "resolution": "unresolved"
        if target is None or attributes.get("proxy_kind") == "unresolved"
        else "source"
        if target.origin.value == "source"
        else "external_or_synthetic",
    }


def candidate_symbol(edge: CodeEdge, graph: CodeGraph, symbols: tuple[str, ...]) -> str | None:
    target = graph.nodes.get(edge.target_id)
    attributes = dict(edge.attributes)
    raw = str(attributes.get("raw_target", target.name if target else edge.target_id))
    label = raw.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
    names = {edge.target_id, raw, label}
    if target is not None:
        names.add(target.name)
    requested = next((symbol for symbol in symbols if symbol in names), None)
    if requested is not None:
        return requested
    if label in DECODER_SYMBOLS:
        return label
    if label in {"decompress", "Decompress", "TryDecompress", "Decompressor", "NewReader"} and (
        "brotli" in raw.lower()
    ):
        return raw
    return fetch_symbol(label, raw, target, attributes)


def fetch_symbol(label: str, raw: str, target: CodeUnit | None, attributes: dict) -> str | None:
    if attributes.get("binding_blocked") or (target and target.origin.value == "source"):
        return None
    if label == "fetch":
        return "fetch"
    if raw.startswith(("undici:", "undici.")) and label in {"request", "stream", "pipeline"}:
        return raw
    return None


def empty_report(root: str, limits: Limits) -> dict:
    return {
        "schema_version": 1,
        "tool": "brotli_source_discovery",
        "trailmark_version": None,
        "root": root,
        "status": "incomplete",
        "coverage": {
            "source_file_counts": {},
            "source_files": None,
            "initial_parsing_bounded": False,
        },
        "limits": asdict(limits),
        "candidates": [],
        "candidate_count": 0,
        "neighborhood": {"nodes": [], "caller_depths": {}, "calls": [], "entrypoints": []},
        "parse_diagnostics": [],
        "parse_diagnostic_count": 0,
        "gaps": [],
        "truncation": dict.fromkeys(
            ("candidates", "caller_nodes", "call_edges", "depth", "diagnostics"), False
        ),
        "limitations": list(LIMITATIONS),
    }


@dataclass
class Neighborhood:
    graph: CodeGraph
    limits: Limits
    truncation: dict
    edges: dict[int, CodeEdge] = field(default_factory=dict)
    depths: dict[str, int] = field(default_factory=dict)
    queue: deque[str] = field(default_factory=deque)

    def add_caller(self, node_id: str, depth: int) -> bool:
        if node_id in self.depths:
            return True
        if len(self.depths) >= self.limits.max_caller_nodes:
            self.truncation["caller_nodes"] = True
            return False
        self.depths[node_id] = depth
        self.queue.append(node_id)
        return True

    def add_edge(self, index: int, edge: CodeEdge) -> bool:
        if index in self.edges:
            return True
        if len(self.edges) >= self.limits.max_call_edges:
            self.truncation["call_edges"] = True
            return False
        self.edges[index] = edge
        return True

    def callers(self, incoming: dict[str, list[tuple[int, CodeEdge]]]) -> None:
        while self.queue:
            node_id = self.queue.popleft()
            depth = self.depths[node_id]
            if depth >= self.limits.max_depth:
                if incoming.get(node_id):
                    self.truncation["depth"] = True
                continue
            if not self.expand(incoming.get(node_id, []), depth):
                break

    def expand(self, incoming: list[tuple[int, CodeEdge]], depth: int) -> bool:
        for index, edge in incoming:
            if not self.add_edge(index, edge):
                return False
            if not self.add_caller(edge.source_id, depth + 1):
                self.edges.pop(index, None)
                return False
        return True

    def unresolved(self, calls: list[tuple[int, CodeEdge]]) -> None:
        unresolved = set(self.graph.unresolved_calls())
        for index, edge in calls:
            if (
                edge.source_id in self.depths
                and edge in unresolved
                and not self.add_edge(index, edge)
            ):
                break

    def report(self) -> dict:
        node_ids = set(self.depths)
        for edge in self.edges.values():
            node_ids.update((edge.source_id, edge.target_id))
        return {
            "nodes": [
                node_row(self.graph.nodes[key])
                for key in sorted(node_ids)
                if key in self.graph.nodes
            ],
            "caller_depths": dict(self.depths),
            "calls": [edge_row(index, edge, self.graph) for index, edge in self.edges.items()],
            "entrypoints": [
                {
                    "node_id": key,
                    "kind": tag.kind.value,
                    "trust_level": tag.trust_level.value,
                    "asset_value": tag.asset_value.value,
                    "description": tag.description,
                }
                for key, tag in self.graph.entrypoints.items()
                if key in self.depths
            ],
        }


def discover(
    graph: CodeGraph,
    version: str,
    limits: Limits,
    symbols: tuple[str, ...] = (),
) -> dict:
    report = empty_report(graph.root_path, limits)
    report["trailmark_version"] = version
    report["coverage"] = {
        "language": graph.language,
        "source_file_counts": dict(graph.source_file_counts),
        "source_files": sum(graph.source_file_counts.values()),
        "initial_parsing_bounded": False,
    }
    neighborhood = Neighborhood(graph, limits, report["truncation"])
    calls = [(index, edge) for index, edge in enumerate(graph.edges) if edge.kind.value == "calls"]
    incoming: dict[str, list[tuple[int, CodeEdge]]] = defaultdict(list)
    for index, edge in calls:
        incoming[edge.target_id].append((index, edge))
        symbol = candidate_symbol(edge, graph, symbols)
        if symbol is not None:
            add_candidate(report, neighborhood, index, edge, symbol)
    neighborhood.callers(incoming)
    neighborhood.unresolved(calls)
    report["neighborhood"] = neighborhood.report()
    finish_report(report, graph, limits)
    return report


def add_candidate(
    report: dict, neighborhood: Neighborhood, index: int, edge: CodeEdge, symbol: str
) -> None:
    report["candidate_count"] += 1
    if len(report["candidates"]) >= neighborhood.limits.max_candidates:
        report["truncation"]["candidates"] = True
        return
    if not neighborhood.add_edge(index, edge):
        return
    neighborhood.add_caller(edge.source_id, 0)
    report["candidates"].append(
        {"symbol": symbol, "call": edge_row(index, edge, neighborhood.graph)}
    )


def finish_report(report: dict, graph: CodeGraph, limits: Limits) -> None:
    report["parse_diagnostics"] = [
        asdict(diagnostic) for diagnostic in graph.parse_diagnostics[: limits.max_diagnostics]
    ]
    report["parse_diagnostic_count"] = len(graph.parse_diagnostics)
    report["truncation"]["diagnostics"] = len(graph.parse_diagnostics) > limits.max_diagnostics
    if not report["coverage"]["source_files"]:
        report["gaps"].append({"kind": "empty_source", "message": "No source files inspected."})
    if graph.parse_diagnostics:
        report["gaps"].append({"kind": "parse_diagnostics", "message": "Source parsing has gaps."})
    if any(report["truncation"].values()):
        report["gaps"].append({"kind": "bounded_output", "message": "Evidence was truncated."})
    report["status"] = "incomplete" if report["gaps"] else "evidence_collected"


def runtime_version() -> str:
    from trailmark import __version__  # noqa: PLC0415 -- Optional runtime dependency.

    if tuple(int(part) for part in __version__.split(".")[:2]) < (0, 7):
        message = "Trailmark >=0.7 is required; use the pinned uv script invocation."
        raise ValueError(message)
    return __version__


def load_graph(root: str, language: str) -> CodeGraph:
    from trailmark.analysis.entrypoints import detect_entrypoints  # noqa: PLC0415
    from trailmark.parse import parse_directory  # noqa: PLC0415
    from tree_sitter_language_pack import Error as LanguageProviderError  # noqa: PLC0415

    try:
        graph = parse_directory(root, language=language, allow_empty=True, strict=False)
        graph.entrypoints.update(detect_entrypoints(graph, root))
    except LanguageProviderError as error:
        message = f"Trailmark language provider failed: {error}"
        raise RuntimeError(message) from error
    return graph


def positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        message = "must be positive"
        raise argparse.ArgumentTypeError(message)
    return number


def nonnegative(value: str) -> int:
    number = int(value)
    if number < 0:
        message = "must be nonnegative"
        raise argparse.ArgumentTypeError(message)
    return number


def arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Source directory; target code is never executed.")
    parser.add_argument(
        "--language", default="auto", help="Trailmark language or comma-separated set."
    )
    parser.add_argument(
        "--symbol", action="append", default=[], help="Also match this exact alias/wrapper name."
    )
    for name in ("max_candidates", "max_caller_nodes", "max_call_edges", "max_diagnostics"):
        parser.add_argument(
            "--" + name.replace("_", "-"), type=positive, default=getattr(Limits(), name)
        )
    parser.add_argument("--max-depth", type=nonnegative, default=Limits().max_depth)
    args = parser.parse_args(argv)
    args.symbol = [symbol.strip() for symbol in args.symbol]
    if any(not symbol for symbol in args.symbol):
        parser.error("--symbol must not be empty")
    return args


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv)
    limits = Limits(**{name: getattr(args, name) for name in asdict(Limits())})
    root = str(args.root)
    report = empty_report(root, limits)
    try:
        root = str(args.root.expanduser().resolve())
        report["root"] = root
        report["trailmark_version"] = runtime_version()
        graph = load_graph(root, args.language)
        report = discover(graph, report["trailmark_version"], limits, tuple(args.symbol))
    except (ImportError, OSError, ValueError, RuntimeError) as error:
        report["gaps"].append({"kind": "discovery_error", "message": str(error)})
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "evidence_collected" else 3


# gremlin: pardon[out_of_scope] CLI bootstrap guard; imports must not launch argparse.
if __name__ == "__main__":
    sys.exit(main())
