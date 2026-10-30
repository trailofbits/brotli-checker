import hashlib
import json

import fuzz_package_provenance as subject
import pytest


@pytest.mark.parametrize("selector", range(7))
def test_fuzz_entry_points_reject_arbitrary_bytes_without_side_effects(selector):
    subject.fuzz_one(bytes((selector,)) + bytes(range(256)))


def test_fuzz_entry_reaches_structured_parser(monkeypatch):
    seen = []

    def parser(text, name):
        seen.append((text, name))

    monkeypatch.setattr(subject, "parse_provenance_json", parser)
    subject.fuzz_one(b"\0" + json.dumps({"bomFormat": "CycloneDX"}).encode())
    assert seen == [('{"bomFormat": "CycloneDX"}', "fuzz.json")]


def test_fuzz_entry_does_not_hide_unexpected_parser_failures(monkeypatch):
    def broken(_text):
        msg = "unexpected invariant failure"
        raise RuntimeError(msg)

    monkeypatch.setattr(subject, "load_vendor_snapshot", broken)
    with pytest.raises(RuntimeError, match="unexpected invariant"):
        subject.fuzz_one(b"\1{}")


def test_fuzz_vendor_snapshot_structured_types_are_expected_rejections():
    malformed = {
        "schema_version": 1,
        "snapshot_date": "2026-10-28",
        "vendor": [],
        "release": "13",
        "assertions": [],
    }
    subject.fuzz_one(b"\1" + json.dumps(malformed).encode())


def test_package_seed_corpus_reaches_every_parser():
    seeds = subject.seed_corpus()
    assert len(seeds) == len(subject.FUZZ_TARGETS)
    assert {value[0] for value in seeds.values()} == set(range(len(subject.FUZZ_TARGETS)))
    for value in seeds.values():
        subject.fuzz_one(value)


def test_package_seed_writer_is_deterministic(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    assert subject.main(["--write-seeds", str(first)]) == 0
    assert subject.main(["--write-seeds", str(second)]) == 0
    first_manifest = json.loads((first / "manifest.json").read_text())
    assert first_manifest == json.loads((second / "manifest.json").read_text())
    for row in first_manifest["seeds"]:
        data = (first / row["name"]).read_bytes()
        assert len(data) == row["size"]
        assert hashlib.sha256(data).hexdigest() == row["sha256"]
        assert data == (second / row["name"]).read_bytes()
