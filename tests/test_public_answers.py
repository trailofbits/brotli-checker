import argparse
import os
from itertools import product

import brotli_binary_data as binary_data
import brotli_inventory as scanner
import brotli_source_discovery as discovery
import pytest
from test_source_discovery import call, decoder_graph


@pytest.mark.parametrize(
    ("function", "arguments", "answer"),
    [
        (scanner.tar_content, (b"",), False),
        (scanner.named_archive_kind, ("decoder.gz",), "gzip"),
        (scanner.safe_text, ("é\u202e",), '"\\u00e9\\u202e"'),
        (scanner.python_bytecode, (b"\0\0\r\n" + bytes(12), "cache.pyc"), True),
        (
            scanner.dependency_matches,
            ("brotli = [", "pyproject.toml"),
            [{"text": "Unparseable Python metadata mentioning Brotli-related components."}],
        ),
        (scanner.positive, ("1",), 1),
        (discovery.positive, ("1",), 1),
    ],
)
def test_public_known_answers(function, arguments, answer):
    assert function(*arguments) == answer


@pytest.mark.parametrize("function", [scanner.positive, discovery.positive])
def test_zero_is_not_a_positive_limit(function):
    with pytest.raises(argparse.ArgumentTypeError, match="positive"):
        function("0")


def test_sparse_byte_operations_agree_with_bytes_at_boundaries(tmp_path, monkeypatch):
    content = bytes(range(256))
    path = tmp_path / "binary"
    path.write_bytes(content)
    monkeypatch.setattr(binary_data, "SEARCH_CHUNK_BYTES", 17)
    original_read, reads = os.pread, 0

    def bounded_read(*args):
        nonlocal reads
        reads += 1
        assert reads < 10_000, "256-byte operations must make bounded progress"
        return original_read(*args)

    monkeypatch.setattr(os, "pread", bounded_read)
    with path.open("rb") as stream, binary_data.file_data(stream) as data:
        for needle, start, stop in product(
            (b"", b"\0", b"\xff", b"\x10\x11", b"missing"),
            (-1, 0, 1, 256, 257),
            (-1, 0, 1, 256, 257),
        ):
            assert data.find(needle, start, stop) == content.find(needle, start, stop)
        for start, stop, step in product((None, -1, 0, 255), (None, -1, 0, 256), (-3, -1, 1, 2, 3)):
            assert data[slice(start, stop, step)] == content[slice(start, stop, step)]
        assert 255 in data
        assert 0 in data


def test_trailmark_neighborhood_capacity_and_duplicate_contracts():
    limits = discovery.Limits(max_caller_nodes=1, max_call_edges=1)
    truncated = dict.fromkeys(("caller_nodes", "call_edges"), False)
    neighborhood = discovery.Neighborhood(decoder_graph(), limits, truncated)
    assert neighborhood.add_caller("app:main", 0) is True
    assert neighborhood.add_caller("app:main", 0) is True
    assert neighborhood.add_caller("app:other", 1) is False
    edge = call("app:main", "app:wrapper")
    assert neighborhood.add_edge(0, edge) is True
    assert neighborhood.add_edge(0, edge) is True
    assert neighborhood.add_edge(1, edge) is False
    assert neighborhood.expand([(1, edge)], 0) is False
    assert truncated == {"caller_nodes": True, "call_edges": True}


def test_fixed_summary_requires_all_checked_statuses():
    rows = [scanner.finding("/src/decoder", "source", status, "fixture") for status in scanner.GOOD]
    assert (
        scanner.summarize({"findings": rows, "coverage": {"gap_count": 0}})["status"]
        == "checked_items_include_fix"
    )
    assert scanner.assess_version("brotli", "1.0.3")["patch_status"] == "potentially_vulnerable"
