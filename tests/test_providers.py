import struct
from pathlib import Path

import brotli_binary_match as matcher
import brotli_providers as providers
from brotli_analysis import AnalysisSession
from brotli_binary_data import sha256_data

LOAD_OFFSET = 0x100
LOAD_ADDRESS = 0x400000
STRING_OFFSET = 0x180
DYNAMIC_OFFSET = 0x800


def dynamic_elf(  # noqa: PLR0913 -- Independent dynamic-tag controls.
    *,
    needed=("libbrotlidec.so.1",),
    soname=None,
    rpath=(),
    runpath=(),
    osabi=0,
    duplicate_load=False,
    terminate=True,
):
    strings = bytearray(b"\0")

    def add(value):
        offset = len(strings)
        strings.extend(value.encode() + b"\0")
        return offset

    tags = [(providers.DT_NEEDED, add(value)) for value in needed]
    if soname:
        tags.append((providers.DT_SONAME, add(soname)))
    tags.extend((providers.DT_RPATH, add(value)) for value in rpath)
    tags.extend((providers.DT_RUNPATH, add(value)) for value in runpath)
    tags.extend(
        [
            (providers.DT_STRTAB, LOAD_ADDRESS + STRING_OFFSET - LOAD_OFFSET),
            (providers.DT_STRSZ, len(strings)),
        ]
    )
    if terminate:
        tags.append((providers.DT_NULL, 0))
    dynamic = b"".join(struct.pack("<qQ", *row) for row in tags)
    phnum = 3 if duplicate_load else 2
    ident = bytearray(b"\x7fELF\x02\x01\x01" + bytes(9))
    ident[7] = osabi
    header = matcher.ELF_HEADER.pack(
        bytes(ident),
        3,
        matcher.EM_X86_64,
        1,
        0,
        matcher.ELF_HEADER.size,
        0,
        0,
        matcher.ELF_HEADER.size,
        matcher.PROGRAM_HEADER.size,
        phnum,
        0,
        0,
        0,
    )
    load = matcher.PROGRAM_HEADER.pack(
        providers.PT_LOAD,
        4,
        LOAD_OFFSET,
        LOAD_ADDRESS,
        LOAD_ADDRESS,
        0x1000,
        0x1000,
        0x1000,
    )
    dynamic_header = matcher.PROGRAM_HEADER.pack(
        providers.PT_DYNAMIC,
        4,
        DYNAMIC_OFFSET,
        LOAD_ADDRESS + DYNAMIC_OFFSET - LOAD_OFFSET,
        0,
        len(dynamic),
        len(dynamic),
        8,
    )
    headers = header + load + (load if duplicate_load else b"") + dynamic_header
    result = bytearray(headers)
    result.extend(bytes(LOAD_OFFSET - len(result)))
    result.extend(bytes(0x1000))
    result[STRING_OFFSET : STRING_OFFSET + len(strings)] = strings
    result[DYNAMIC_OFFSET : DYNAMIC_OFFSET + len(dynamic)] = dynamic
    return bytes(result)


def artifact(identifier, path, loader, *, namespace="deployment:image", boundary="/"):
    return {
        "id": identifier,
        "path": path,
        "logical_path": path,
        "namespace": namespace,
        "boundary": boundary,
        "deployment_root": namespace.startswith("deployment:"),
        "loader": loader,
    }


def record(session, data, path, depth=0):
    return session.record(data, path, sha256_data(data), depth)


def test_dynamic_strings_identity_and_runpath_precedence():
    result = providers.elf_dependencies(
        dynamic_elf(
            soname="app",
            rpath=("/wrong",),
            runpath=("$ORIGIN/../lib",),
        )
    )
    assert result["needed"] == ["libbrotlidec.so.1"]
    assert result["soname"] == "app"
    assert result["rpath"] == ["/wrong"]
    assert result["runpath"] == ["$ORIGIN/../lib"]
    assert result["identity"] == {
        "machine": matcher.EM_X86_64,
        "bits": 64,
        "byteorder": "little",
        "osabi": 0,
        "abi_version": 0,
        "abi_flags": 0,
    }


def test_duplicate_load_mapping_never_silently_selects_dynamic_strings():
    result = providers.elf_dependencies(dynamic_elf(duplicate_load=True))
    assert result["needed"] == []
    assert any("unique file-backed mapping" in gap for gap in result["gaps"])


def test_dynamic_string_mapping_is_resolved_once_for_many_names(monkeypatch):
    calls = 0
    original = providers._mapped_string_table  # noqa: SLF001 -- CPU-boundary regression.

    def counted(*args):
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(providers, "_mapped_string_table", counted)
    result = providers.elf_dependencies(
        dynamic_elf(needed=tuple(f"library-{index}.so" for index in range(100)))
    )
    assert len(result["needed"]) == 100
    assert calls == 1


def test_malformed_dynamic_terminator_offsets_strings_and_budget_fail_closed(monkeypatch):
    missing_null = providers.elf_dependencies(dynamic_elf(terminate=False))
    bad_offset_data = bytearray(dynamic_elf())
    struct.pack_into("<Q", bad_offset_data, DYNAMIC_OFFSET + 8, 0xFFFF)
    bad_offset = providers.elf_dependencies(bytes(bad_offset_data))
    control_data = bytearray(dynamic_elf())
    control_data[STRING_OFFSET + 1] = 1
    control = providers.elf_dependencies(bytes(control_data))
    monkeypatch.setattr(providers, "MAX_DYNAMIC_ENTRIES", 1)
    budget = providers.elf_dependencies(dynamic_elf())
    assert any("terminating DT_NULL" in gap for gap in missing_null["gaps"])
    assert any("outside DT_STRSZ" in gap for gap in bad_offset["gaps"])
    assert any("control-containing" in gap for gap in control["gaps"])
    assert any("entry budget" in gap for gap in budget["gaps"])


def test_origin_runpath_selects_only_same_namespace_abi_candidate():
    importer_loader = providers.elf_dependencies(dynamic_elf(runpath=("$ORIGIN/../lib",)))
    provider_loader = providers.elf_dependencies(dynamic_elf(needed=(), soname="libbrotlidec.so.1"))
    wrong_loader = {**provider_loader, "identity": {**provider_loader["identity"], "osabi": 9}}
    graph = providers.provider_graph(
        [
            artifact("app", "/bin/app", importer_loader),
            artifact("right", "/lib/libbrotlidec.so.1", provider_loader),
            artifact("wrong", "/lib/wrong/libbrotlidec.so.1", wrong_loader),
            artifact(
                "other-namespace",
                "/lib/libbrotlidec.so.1",
                provider_loader,
                namespace="deployment:other",
            ),
        ]
    )
    edge = graph["edges"][0]
    assert edge["targets"] == ["right"]
    assert edge["status"] == "scope_unique_candidate"
    assert edge["basis"] == "declared_runpath"
    assert edge["runtime_selection"] == "unknown"


def test_wrong_abi_and_duplicate_soname_remain_conservative():
    importer = providers.elf_dependencies(dynamic_elf())
    provider = providers.elf_dependencies(dynamic_elf(needed=(), soname="libbrotlidec.so.1"))
    wrong = {**provider, "identity": {**provider["identity"], "osabi": 3}}
    incompatible = providers.provider_graph(
        [artifact("app", "/bin/app", importer), artifact("wrong", "/lib/a.so", wrong)]
    )
    ambiguous = providers.provider_graph(
        [
            artifact("app", "/bin/app", importer),
            artifact("one", "/lib/one.so", provider),
            artifact("two", "/usr/lib/two.so", provider),
        ]
    )
    assert incompatible["edges"][0]["status"] == "incompatible_candidates"
    assert incompatible["edges"][0]["targets"] == []
    assert ambiguous["edges"][0]["status"] == "ambiguous_candidates"
    assert ambiguous["edges"][0]["targets"] == ["one", "two"]


def test_loader_paths_cannot_escape_or_smuggle_origin_tokens():
    provider = providers.elf_dependencies(dynamic_elf(needed=(), soname="libbrotlidec.so.1"))
    for value in ("$ORIGIN/../../outside", "$ORIGINevil/lib"):
        importer = providers.elf_dependencies(dynamic_elf(runpath=(value,)))
        result = providers.provider_graph(
            [
                artifact(
                    "app",
                    "/scope/bin/app",
                    importer,
                    namespace="filesystem",
                    boundary="/scope",
                ),
                artifact(
                    "outside",
                    "/outside/libbrotlidec.so.1",
                    provider,
                    namespace="filesystem",
                    boundary="/scope",
                ),
            ]
        )
        assert result["edges"][0]["status"] == "unsupported_search_path"
        assert result["edges"][0]["targets"] == []
        assert result["gaps"]


def test_path_bearing_needed_and_relative_runpath_are_unsupported():
    identity = providers.elf_dependencies(dynamic_elf(needed=()))["identity"]
    for loader in (
        {
            "needed": ["../lib/x.so"],
            "soname": None,
            "runpath": [],
            "rpath": [],
            "identity": identity,
        },
        {
            "needed": ["x.so"],
            "soname": None,
            "runpath": ["relative"],
            "rpath": [],
            "identity": identity,
        },
    ):
        result = providers.provider_graph([artifact("app", "/bin/app", loader)])
        assert result["edges"][0]["status"] == "unsupported_search_path"
        assert result["edges"][0]["targets"] == []


def test_analysis_deployment_root_uses_virtual_paths_without_host_loader_selection():
    root = Path("/image")
    session = AnalysisSession([root], deployment_roots=[root], xrefs=False)
    app = record(
        session,
        dynamic_elf(runpath=("$ORIGIN/../lib",)),
        "/image/bin/app",
    )
    library = record(
        session,
        dynamic_elf(needed=(), soname="libbrotlidec.so.1"),
        "/image/lib/libbrotlidec.so.1",
    )
    result = session.finish()
    edge = result["relations"][0]
    assert (edge["source"], edge["targets"]) == (app["id"], [library["id"]])
    assert edge["runtime_selection"] == "unknown"
    assert result["gaps"] == []


def test_archive_virtual_root_never_joins_same_named_filesystem_provider():
    session = AnalysisSession([Path("/supplied")], xrefs=False)
    archive = record(session, b"archive", "/supplied/app.tar")
    app = record(
        session,
        dynamic_elf(runpath=("$ORIGIN/../../../../lib",)),
        "/supplied/app.tar!usr/bin/app",
        1,
    )
    member = record(
        session,
        dynamic_elf(needed=(), soname="libbrotlidec.so.1"),
        "/supplied/app.tar!lib/libbrotlidec.so.1",
        1,
    )
    host = record(
        session,
        dynamic_elf(needed=(), soname="libbrotlidec.so.1"),
        "/supplied/lib/libbrotlidec.so.1",
    )
    result = session.finish()
    edge = next(item for item in result["relations"] if item["source"] == app["id"])
    assert archive["id"] == app["namespace"] == member["namespace"]
    assert host["namespace"] != member["namespace"]
    assert edge["targets"] == [member["id"]]
