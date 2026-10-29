import struct
from pathlib import Path

import brotli_binary_match as matcher
import brotli_providers as providers
import pytest
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


def dynamic_elf32_be():
    strings = b"\0libbrotlidec.so.1\0$ORIGIN/../lib\0"
    needed_offset = 1
    runpath_offset = strings.index(b"$ORIGIN")
    tags = (
        (providers.DT_NEEDED, needed_offset),
        (providers.DT_RUNPATH, runpath_offset),
        (providers.DT_STRTAB, LOAD_ADDRESS + STRING_OFFSET - LOAD_OFFSET),
        (providers.DT_STRSZ, len(strings)),
        (providers.DT_NULL, 0),
    )
    layout = matcher.ELFLayout(32, "big")
    header_parser = layout.parser("header")
    program_parser = layout.parser("program")
    dynamic_parser = struct.Struct(">iI")
    dynamic = b"".join(dynamic_parser.pack(*row) for row in tags)
    ident = b"\x7fELF\x01\x02\x01" + bytes(9)
    header = header_parser.pack(
        ident,
        3,
        matcher.EM_MIPS,
        1,
        0,
        header_parser.size,
        0,
        0x50001007,
        header_parser.size,
        program_parser.size,
        2,
        0,
        0,
        0,
    )
    load = program_parser.pack(
        providers.PT_LOAD,
        LOAD_OFFSET,
        LOAD_ADDRESS,
        LOAD_ADDRESS,
        0x1000,
        0x1000,
        4,
        0x1000,
    )
    dynamic_header = program_parser.pack(
        providers.PT_DYNAMIC,
        DYNAMIC_OFFSET,
        LOAD_ADDRESS + DYNAMIC_OFFSET - LOAD_OFFSET,
        0,
        len(dynamic),
        len(dynamic),
        4,
        4,
    )
    result = bytearray(header + load + dynamic_header)
    result.extend(bytes(LOAD_OFFSET - len(result)))
    result.extend(bytes(0x1000))
    result[STRING_OFFSET : STRING_OFFSET + len(strings)] = strings
    result[DYNAMIC_OFFSET : DYNAMIC_OFFSET + len(dynamic)] = dynamic
    return bytes(result)


def set_dynamic_size(data, size):
    result = bytearray(data)
    header = matcher.elf_header(bytes(result))
    parser = matcher.ELFLayout.of(header).parser("program")
    dynamic_header = list(parser.unpack_from(result, header[5] + parser.size))
    dynamic_header[4] = size
    dynamic_header[5] = size
    parser.pack_into(result, header[5] + parser.size, *dynamic_header)
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


def test_dynamic_string_table_mapping_enforces_both_file_backed_boundaries():
    map_table = providers._mapped_string_table  # noqa: SLF001 -- Parser boundary contract.
    segments = [(providers.PT_LOAD, 0, 8, 0x100, 0, 16, 16, 1)]
    assert map_table(bytes(24), segments, 0x100, 16) == 8
    with pytest.raises(ValueError, match="unique file-backed mapping"):
        map_table(bytes(24), segments, 0x100, 17)
    with pytest.raises(ValueError, match="unique file-backed mapping"):
        map_table(bytes(23), segments, 0x100, 16)


def test_dynamic_string_bounds_accept_exact_limits_and_reject_adjacent_values(monkeypatch):
    map_string = providers._mapped_string  # noqa: SLF001 -- Parser boundary contract.
    monkeypatch.setattr(providers, "MAX_STRING_BYTES", 3)
    assert map_string(b"abc\0", 0, 4, 0) == "abc"
    assert map_string(b" \0", 0, 2, 0) == " "
    for data, size, offset, reason in (
        (b"abcx\0", 5, 0, "Unterminated or oversized"),
        (b"abc\0", 4, 4, "outside DT_STRSZ"),
        (b"abc\0", 4, -1, "outside DT_STRSZ"),
        (b"xabc\0", 4, 1, "Unterminated or oversized"),
        (b"\0", 1, 0, "Empty or control-containing"),
        (b"\x1f\0", 2, 0, "Empty or control-containing"),
    ):
        with pytest.raises(ValueError, match=reason):
            map_string(data, 0, size, offset)


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


def test_dynamic_parser_supports_elf32_big_endian_and_preserves_abi_flags():
    result = providers.elf_dependencies(dynamic_elf32_be())
    assert result["gaps"] == []
    assert result["needed"] == ["libbrotlidec.so.1"]
    assert result["runpath"] == ["$ORIGIN/../lib"]
    assert result["identity"] == {
        "machine": matcher.EM_MIPS,
        "bits": 32,
        "byteorder": "big",
        "osabi": 0,
        "abi_version": 0,
        "abi_flags": 0x50001007,
    }


def test_dynamic_extent_accepts_exact_file_end_but_rejects_partial_entry():
    data = dynamic_elf()
    exact = providers.elf_dependencies(set_dynamic_size(data, len(data) - DYNAMIC_OFFSET))
    partial = providers.elf_dependencies(set_dynamic_size(data, 15))
    assert exact["needed"] == ["libbrotlidec.so.1"]
    assert exact["gaps"] == []
    assert any("Malformed PT_DYNAMIC extent" in gap for gap in partial["gaps"])


def test_dynamic_tables_require_each_unique_metadata_tag():
    data = bytearray(dynamic_elf())
    struct.pack_into("<q", data, DYNAMIC_OFFSET + 2 * 16, 0x1234)
    result = providers.elf_dependencies(bytes(data))
    assert result["needed"] == []
    assert any("unique DT_STRTAB and DT_STRSZ" in gap for gap in result["gaps"])


def test_empty_dynamic_metadata_retains_the_stable_result_shape():
    data = bytearray(dynamic_elf())
    for offset in range(DYNAMIC_OFFSET, DYNAMIC_OFFSET + 3 * 16, 16):
        struct.pack_into("<q", data, offset, 0x1234)
    result = providers.elf_dependencies(bytes(data))
    assert result["needed"] == []
    assert result["soname"] is None
    assert result["rpath"] == []
    assert result["runpath"] == []
    assert result["gaps"] == []
    assert result["identity"]["machine"] == matcher.EM_X86_64


def test_dynamic_entry_and_string_budgets_accept_exact_limit(monkeypatch):
    monkeypatch.setattr(providers, "MAX_DYNAMIC_ENTRIES", 4)
    assert providers.elf_dependencies(dynamic_elf())["gaps"] == []
    monkeypatch.setattr(providers, "MAX_DYNAMIC_ENTRIES", 3)
    assert any("entry budget" in gap for gap in providers.elf_dependencies(dynamic_elf())["gaps"])

    monkeypatch.setattr(providers, "MAX_DYNAMIC_ENTRIES", 16)
    monkeypatch.setattr(providers, "MAX_DYNAMIC_STRINGS", 2)
    assert providers.elf_dependencies(dynamic_elf(needed=("one", "two")))["needed"] == [
        "one",
        "two",
    ]
    assert any(
        "string count" in gap
        for gap in providers.elf_dependencies(dynamic_elf(needed=("one", "two", "three")))["gaps"]
    )


def test_duplicate_singleton_dynamic_string_tag_is_rejected():
    data = bytearray(dynamic_elf(needed=(), soname="one", rpath=("two",)))
    struct.pack_into("<q", data, DYNAMIC_OFFSET + 16, providers.DT_SONAME)
    result = providers.elf_dependencies(bytes(data))
    assert result["soname"] is None
    assert any("singleton constraint" in gap for gap in result["gaps"])


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
    assert graph["complete"] is True


def test_rpath_fallback_and_mixed_runpath_components_preserve_valid_candidate():
    provider = providers.elf_dependencies(dynamic_elf(needed=(), soname="libbrotlidec.so.1"))
    for field, basis in (("rpath", "declared_rpath"), ("runpath", "declared_runpath")):
        importer = providers.elf_dependencies(dynamic_elf(**{field: ("relative:$ORIGIN/../lib",)}))
        graph = providers.provider_graph(
            [
                artifact("app", "/bin/app", importer),
                artifact("library", "/lib/libbrotlidec.so.1", provider),
            ]
        )
        edge = graph["edges"][0]
        assert edge["targets"] == ["library"]
        assert edge["status"] == "scope_unique_candidate"
        assert edge["basis"] == basis
        assert graph["complete"] is False
        assert graph["gaps"]


def test_absolute_loader_path_requires_and_uses_explicit_deployment_root():
    importer = providers.elf_dependencies(dynamic_elf(runpath=("/lib",)))
    provider = providers.elf_dependencies(dynamic_elf(needed=(), soname="libbrotlidec.so.1"))
    unrooted = artifact(
        "app",
        "/image/bin/app",
        importer,
        namespace="filesystem",
        boundary="/image",
    )
    rooted = artifact("app", "/bin/app", importer)
    candidate = artifact("library", "/lib/libbrotlidec.so.1", provider)

    unsupported = providers.provider_graph([unrooted, candidate])
    selected = providers.provider_graph([rooted, candidate])
    assert unsupported["edges"][0]["status"] == "unsupported_search_path"
    assert unsupported["edges"][0]["targets"] == []
    assert unsupported["complete"] is False
    assert selected["edges"][0]["status"] == "scope_unique_candidate"
    assert selected["edges"][0]["targets"] == ["library"]
    assert selected["complete"] is True


@pytest.mark.parametrize(
    "logical_path",
    ["bin/app", "/bin\\app", "/bin/../bin/app"],
    ids=["relative", "backslash", "non-normalized"],
)
def test_malformed_importer_logical_path_fails_closed(logical_path):
    importer = providers.elf_dependencies(dynamic_elf(runpath=("$ORIGIN/../lib",)))
    graph = providers.provider_graph([artifact("app", logical_path, importer)])
    assert graph["edges"][0]["status"] == "unsupported_search_path"
    assert graph["edges"][0]["targets"] == []
    assert graph["complete"] is False


@pytest.mark.parametrize(
    "boundary",
    ["scope", "/scope\\root", "/scope/../scope", "/scope/"],
    ids=["relative", "backslash", "non-normalized", "trailing-slash"],
)
def test_malformed_scope_boundary_fails_closed(boundary):
    importer = providers.elf_dependencies(dynamic_elf(runpath=("$ORIGIN/../lib",)))
    graph = providers.provider_graph(
        [
            artifact(
                "app",
                "/scope/bin/app",
                importer,
                namespace="filesystem",
                boundary=boundary,
            )
        ]
    )
    assert graph["edges"][0]["status"] == "unsupported_search_path"
    assert graph["edges"][0]["targets"] == []
    assert graph["complete"] is False


def test_unsupported_loader_path_components_are_never_candidate_paths():
    identity = providers.elf_dependencies(dynamic_elf(needed=()))["identity"]
    for declaration in ("$ORIGIN/$UNKNOWN", "/lib\\foreign"):
        importer = artifact(
            "app",
            "/bin/app",
            {
                "needed": ["libbrotlidec.so.1"],
                "soname": None,
                "rpath": [],
                "runpath": [declaration],
                "identity": identity,
            },
        )
        paths, gaps, basis = providers._candidate_paths(  # noqa: SLF001
            importer, "libbrotlidec.so.1"
        )
        assert paths == set()
        assert gaps == ["Empty, unsupported-token, or non-POSIX loader path"]
        assert basis == "declared_runpath"


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
        assert result["complete"] is False


def test_provider_edge_budget_retains_only_complete_edges(monkeypatch):
    monkeypatch.setattr(providers, "MAX_PROVIDER_EDGES", 1)
    one = providers.provider_graph(
        [artifact("one", "/bin/one", providers.elf_dependencies(dynamic_elf()))]
    )
    two = providers.provider_graph(
        [
            artifact(
                "two",
                "/bin/two",
                providers.elf_dependencies(
                    dynamic_elf(needed=("libbrotlidec.so.1", "libbrotlicommon.so.1"))
                ),
            )
        ]
    )
    assert len(one["edges"]) == 1
    assert one["complete"] is True
    assert len(two["edges"]) == 1
    assert two["complete"] is False
    assert two["gaps"] == ["Provider edge budget exceeded"]


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
