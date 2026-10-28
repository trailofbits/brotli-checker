import gzip
import io
import json
import stat
import struct
import tarfile
from types import SimpleNamespace

import brotli_payloads as payloads
import pytest
from brotli_binary_data import file_data


def ar_member(name, content):
    header = (
        name.encode().ljust(16)
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + str(len(content)).encode().ljust(10)
        + b"`\n"
    )
    return header + content + (b"\n" if len(content) & 1 else b"")


def ar_archive(*members):
    return payloads.AR_MAGIC + b"".join(ar_member(name, content) for name, content in members)


def cpio_newc(entries, *, crc=False):
    output = bytearray()
    magic = b"070702" if crc else b"070701"
    for index, (name, content, mode) in enumerate(entries):
        raw_name = name.encode() + b"\0"
        checksum = sum(content) & 0xFFFFFFFF if crc else 0
        values = [index + 1, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(raw_name), checksum]
        output.extend(magic + b"".join(f"{value:08x}".encode() for value in values))
        output.extend(raw_name)
        output.extend(bytes((-len(output)) & 3))
        output.extend(content)
        output.extend(bytes((-len(output)) & 3))
    raw_name = b"TRAILER!!!\0"
    values = [0, stat.S_IFREG, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(raw_name), 0]
    output.extend(magic + b"".join(f"{value:08x}".encode() for value in values))
    output.extend(raw_name)
    output.extend(bytes((-len(output)) & 3))
    return bytes(output)


def cpio_odc(entries):
    output = bytearray()
    for index, (name, content, mode) in enumerate([*entries, ("TRAILER!!!", b"", stat.S_IFREG)]):
        raw_name = name.encode() + b"\0"
        fields = [0, index + 1, mode, 0, 0, 1, 0]
        header = (
            b"070707"
            + b"".join(f"{value:06o}".encode() for value in fields)
            + f"{0:011o}{len(raw_name):06o}{len(content):011o}".encode()
        )
        assert len(header) == 76
        output.extend(header + raw_name + content)
    return bytes(output)


def rpm_header(tags):
    store = bytearray()
    entries = []
    for tag, value in tags:
        if isinstance(value, str):
            encoded = value.encode() + b"\0"
            entries.append((tag, 6, len(store), 1))
            store.extend(encoded)
        elif value and all(isinstance(item, int) for item in value):
            store.extend(bytes((-len(store)) & 3))
            entries.append((tag, 4, len(store), len(value)))
            store.extend(b"".join(struct.pack(">I", item) for item in value))
        else:
            entries.append((tag, 8, len(store), len(value)))
            store.extend(b"".join(item.encode() + b"\0" for item in value))
    return (
        b"\x8e\xad\xe8\x01"
        + bytes(4)
        + struct.pack(">II", len(entries), len(store))
        + b"".join(struct.pack(">IIII", *entry) for entry in entries)
        + store
    )


def rpm_fixture(cpio, compressor="gzip"):
    lead = bytearray(96)
    lead[:4] = payloads.RPM_MAGIC
    signature = rpm_header([])
    padding = bytes((-(len(lead) + len(signature))) & 7)
    main = rpm_header(
        [
            (1000, "fixture"),
            (1003, [2]),
            (1001, "1.2.3"),
            (1002, "4"),
            (1022, "aarch64"),
            (1124, "cpio"),
            (1125, compressor),
            (1126, "9"),
            (1117, ["tool"]),
            (1118, ["/usr/bin/"]),
            (1116, [0]),
            (1035, ["a" * 64]),
            (5011, [8]),
        ]
    )
    compressed = {
        "none": lambda value: value,
        "gzip": gzip.compress,
        "bzip2": payloads.bz2.compress,
        "xz": payloads.lzma.compress,
        "lzma": lambda value: payloads.lzma.compress(value, format=payloads.lzma.FORMAT_ALONE),
    }[compressor](cpio)
    return bytes(lead) + signature + padding + main + compressed


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = content.decode()
                archive.addfile(info)
    return output.getvalue()


def docker_save(layers):
    manifest = json.dumps(
        [{"Config": "config.json", "RepoTags": [], "Layers": list(layers)}]
    ).encode()
    entries = [("manifest.json", manifest, "file"), ("config.json", b"{}", "file")]
    entries.extend((name, content, "file") for name, content in layers.items())
    return tar_bytes(entries)


def test_oci_probe_does_not_apply_oci_name_rules_to_ordinary_tar():
    ordinary = tar_bytes([("hostile\nname", b"data", "file")])
    assert not payloads.oci_archive_candidate(ordinary)
    image = docker_save({"layer/layer.tar": tar_bytes([("app/file", b"data", "file")])})
    assert payloads.oci_archive_candidate(image)


def test_ar_and_deb_members_are_slice_streams_without_extraction():
    archive = ar_archive(
        ("debian-binary/", b"2.0\n"),
        ("control.tar.gz/", b"control"),
        ("data.tar.xz/", b"payload"),
    )
    assert payloads.payload_kind(archive, "renamed") == "deb"
    members = list(payloads.iter_deb_members(archive))
    assert [member.name for member in members] == ["control.tar.gz", "data.tar.xz"]
    with members[1].open() as stream:
        assert stream.read() == b"payload"


def test_ar_members_retain_sparse_filedata_offsets(tmp_path):
    target = tmp_path / "lib.a"
    target.write_bytes(ar_archive(("member.o/", b"object bytes")))
    with target.open("rb") as stream, file_data(stream) as data:
        member = next(payloads.iter_ar_members(data))
        assert member.file_offset == 68
        assert member.read() == b"object bytes"


def test_ar_supports_gnu_and_bsd_names_and_rejects_traversal():
    string_table = b"long-name.o/\n"
    archive = payloads.AR_MAGIC + ar_member("//", string_table) + ar_member("/0", b"object")
    assert [(member.name, member.read()) for member in payloads.iter_ar_members(archive)] == [
        ("long-name.o", b"object")
    ]
    bsd_name = b"bsd-name.o"
    bsd = payloads.AR_MAGIC + ar_member(f"#1/{len(bsd_name)}", bsd_name + b"bytes")
    assert next(payloads.iter_ar_members(bsd)).read() == b"bytes"
    unsafe = payloads.AR_MAGIC + ar_member("../escape/", b"x")
    with pytest.raises(payloads.PayloadError, match="parent-traversing"):
        list(payloads.iter_ar_members(unsafe))
    assert payloads.payload_kind(ar_archive(*[(f"f{i}/", b"x") for i in range(12)])) == "ar"
    with pytest.raises(payloads.PayloadError, match="member exceeds"):
        list(
            payloads.iter_ar_members(
                ar_archive(("large/", b"1234")),
                payloads.PayloadLimits(max_member_bytes=3),
            )
        )


def test_ar_and_deb_malformed_headers_fail_before_member_use():
    valid = bytearray(ar_archive(("member/", b"data")))
    bad_trailer = valid.copy()
    bad_trailer[66:68] = b"xx"
    bad_size = valid.copy()
    bad_size[56:66] = b"not-size  "
    for artifact, reason in ((bad_trailer, "trailer"), (bad_size, "size")):
        with pytest.raises(payloads.PayloadError, match=reason):
            list(payloads.iter_ar_members(bytes(artifact)))
    with pytest.raises(payloads.PayloadError, match="GNU ar name offset"):
        list(payloads.iter_ar_members(payloads.AR_MAGIC + ar_member("/0", b"data")))
    with pytest.raises(payloads.PayloadError, match="exact debian-binary"):
        list(payloads.iter_deb_members(ar_archive(("debian-binary/", b"2.1\n"))))


def test_cpio_newc_crc_paths_types_and_limits():
    archive = cpio_newc([("usr/lib/libbrotli.so", b"decoder", stat.S_IFREG | 0o644)], crc=True)
    members = list(payloads.iter_cpio_members(archive))
    assert [(member.name, member.kind, member.read()) for member in members] == [
        ("usr/lib/libbrotli.so", "file", b"decoder")
    ]
    corrupted = archive.replace(b"decoder", b"Dec0der")
    with pytest.raises(payloads.PayloadError, match="checksum"):
        list(payloads.iter_cpio_members(corrupted))
    with pytest.raises(payloads.PayloadError, match="member count"):
        list(payloads.iter_cpio_members(archive, payloads.PayloadLimits(max_members=0)))
    unsafe = cpio_newc([("../escape", b"x", stat.S_IFREG | 0o644)])
    with pytest.raises(payloads.PayloadError, match="parent-traversing"):
        list(payloads.iter_cpio_members(unsafe))


def test_cpio_odc_uses_76_byte_header_and_correct_field_indices():
    archive = cpio_odc(
        [
            ("usr/lib/libbrotli.so", b"decoder", stat.S_IFREG | 0o644),
            ("usr/lib/link", b"libbrotli.so", stat.S_IFLNK | 0o777),
        ]
    )
    members = list(payloads.iter_cpio_members(archive))
    assert [(member.name, member.kind, member.read()) for member in members] == [
        ("usr/lib/libbrotli.so", "file", b"decoder"),
        ("usr/lib/link", "symlink", b"libbrotli.so"),
    ]
    malformed = bytearray(archive)
    malformed[6:12] = b"xxxxxx"
    with pytest.raises(payloads.PayloadError, match="odc numeric"):
        list(payloads.iter_cpio_members(bytes(malformed)))


def test_rpm_header_provenance_and_streamed_gzip_cpio():
    cpio = cpio_newc([("usr/bin/tool", b"ELF", stat.S_IFREG | 0o755)])
    rpm = payloads.rpm_payload(rpm_fixture(cpio))
    assert rpm.metadata == {
        "name": "fixture",
        "epoch": 2,
        "version": "1.2.3",
        "release": "4",
        "arch": "aarch64",
        "payload_format": "cpio",
        "payload_flags": "9",
        "payload_compressor": "gzip",
        "file_digest_algorithm": 8,
        "file_digests": [{"path": "usr/bin/tool", "digest": "a" * 64, "algorithm": 8}],
    }
    with payloads.open_rpm_payload(rpm) as stream:
        expanded = stream.read()
    assert next(payloads.iter_cpio_members(expanded)).read() == b"ELF"
    assert next(payloads.iter_rpm_members(rpm)).read() == b"ELF"
    with pytest.raises(payloads.PayloadError, match="payload format"):
        payloads.rpm_payload(rpm_fixture(cpio).replace(b"cpio\0", b"drpm\0"))
    assert next(payloads.iter_payload_members(rpm_fixture(cpio), "rpm")).name == "usr/bin/tool"
    oversized = bytearray(112)
    oversized[:4] = payloads.RPM_MAGIC
    oversized[96:104] = b"\x8e\xad\xe8\x01\0\0\0\0"
    struct.pack_into(">II", oversized, 104, payloads.MAX_ITEMS + 1, 0)
    with pytest.raises(payloads.PayloadError, match="header count"):
        payloads.rpm_payload(bytes(oversized))


@pytest.mark.parametrize("compressor", ["none", "bzip2", "xz", "lzma"])
def test_rpm_supported_payload_compressors_stream_to_cpio(compressor):
    cpio = cpio_newc([("usr/bin/tool", b"ELF", stat.S_IFREG | 0o755)])
    rpm = payloads.rpm_payload(rpm_fixture(cpio, compressor))
    assert next(payloads.iter_rpm_members(rpm)).read() == b"ELF"


def test_rpm_rejects_unknown_compressor_before_payload_read():
    cpio = cpio_newc([])
    unknown = rpm_fixture(cpio).replace(b"gzip\0", b"bruh\0")
    with pytest.raises(payloads.PayloadError, match="compressor"):
        payloads.rpm_payload(unknown)


def test_zstd_unavailable_is_explicit_not_opaque(monkeypatch):
    def unavailable(_name):
        raise ImportError

    monkeypatch.setattr(payloads.importlib, "import_module", unavailable)
    with (
        pytest.raises(payloads.PayloadUnavailableError, match="optional"),
        payloads.open_zstd(payloads.ZSTD_MAGIC + bytes(8)),
    ):
        pass


def test_zstd_backend_data_error_is_normalized_at_provider_boundary(monkeypatch):
    class BackendError(Exception):
        pass

    class BrokenStream(io.BytesIO):
        def read(self, _size=-1):
            raise BackendError

    module = SimpleNamespace(
        ZstdError=BackendError,
        ZstdFile=lambda _source, _mode: BrokenStream(),
    )
    monkeypatch.setattr(payloads.importlib, "import_module", lambda _name: module)
    with (
        pytest.raises(payloads.PayloadError, match="invalid Zstandard"),
        payloads.open_zstd(payloads.ZSTD_MAGIC + b"broken") as stream,
    ):
        stream.read()


def test_optional_zstd_stream_is_used_for_oci_layer(monkeypatch):
    layer = tar_bytes([("app/file", b"data", "file")])

    def optional(name):
        if name == "compression.zstd":
            return SimpleNamespace(ZstdFile=lambda source, _mode: io.BytesIO(source.read()[4:]))
        raise ImportError

    monkeypatch.setattr(payloads.importlib, "import_module", optional)
    image = payloads.apply_oci_layers(
        [("zstd-layer", payloads.ZSTD_MAGIC + layer, "application/vnd.oci.image.layer.v1.tar+zstd")]
    )
    assert image.members[0].read() == b"data"
    expanded = next(payloads.iter_payload_members(payloads.ZSTD_MAGIC + b"plain", "zstd"))
    assert expanded.read() == b"plain"
    skippable = docker_save({"layer.zst": payloads.ZSTD_MAGICS[1] + layer})
    with payloads.open_oci_filesystems(skippable) as images:
        assert images[0].members[0].read() == b"data"


def test_oci_layers_apply_whiteout_and_opaque_directory_to_final_filesystem():
    first = tar_bytes(
        [
            ("app/old", b"old", "file"),
            ("dir/a", b"a", "file"),
            ("link", b"app/old", "symlink"),
        ]
    )
    second = tar_bytes(
        [
            ("app/new", b"new", "file"),
            ("app/.wh.old", b"", "file"),
            ("dir/b", b"b", "file"),
            ("dir/.wh..wh..opq", b"", "file"),
        ]
    )
    image = payloads.oci_filesystems(
        docker_save({"layer1/layer.tar": first, "layer2/layer.tar": second})
    )[0]
    assert [(member.name, member.read()) for member in image.members] == [
        ("app/new", b"new"),
        ("dir/b", b"b"),
    ]
    assert any(
        row["action"] == "whiteout" and row["removed"] == ["app/old"] for row in image.history
    )
    assert any(row["action"] == "opaque" and row["removed"] == ["dir/a"] for row in image.history)
    assert image.gaps == ("Layer layer1/layer.tar nonregular member not followed: link",)
    assert all(member.metadata["final"] is True for member in image.members)


def test_production_oci_reader_keeps_uncompressed_members_as_outer_slices():
    layer = tar_bytes([("app/file", b"visible", "file")])
    archive = docker_save({"layer.tar": layer})
    with payloads.open_oci_filesystems(archive) as images:
        member = images[0].members[0]
        assert member.data is archive
        assert member.read() == b"visible"
        assert member.file_offset > 0
    assert next(payloads.iter_payload_members(archive, "oci")).read() == b"visible"


def test_production_oci_reader_spools_only_compressed_layer_for_context_lifetime():
    compressed = gzip.compress(tar_bytes([("app/file", b"visible", "file")]))
    archive = docker_save({"layer.tar.gz": compressed})
    with payloads.open_oci_filesystems(archive) as images:
        member = images[0].members[0]
        assert member.data is not archive
        assert member.read() == b"visible"


def test_production_oci_reader_applies_whiteouts_before_exposing_members():
    first = tar_bytes([("app/old", b"old", "file"), ("dir/a", b"a", "file")])
    second = tar_bytes(
        [
            ("app/.wh.old", b"", "file"),
            ("dir/.wh..wh..opq", b"", "file"),
            ("dir/new", b"new", "file"),
        ]
    )
    archive = docker_save({"one.tar": first, "two.tar": second})
    with payloads.open_oci_filesystems(archive) as images:
        assert [(member.name, member.read()) for member in images[0].members] == [
            ("dir/new", b"new")
        ]
        assert {row["action"] for row in images[0].history} >= {"whiteout", "opaque"}


def test_production_oci_reader_rejects_invalid_manifest_and_missing_layer():
    malformed = tar_bytes([("manifest.json", b"{}", "file")])
    with (
        pytest.raises(payloads.PayloadError, match="manifest population"),
        payloads.open_oci_filesystems(malformed),
    ):
        pass
    missing = tar_bytes(
        [
            (
                "manifest.json",
                json.dumps(
                    [{"Config": "config.json", "RepoTags": [], "Layers": ["gone"]}]
                ).encode(),
                "file",
            )
        ]
    )
    with (
        pytest.raises(payloads.PayloadError, match="missing layer"),
        payloads.open_oci_filesystems(missing),
    ):
        pass


def test_oci_does_not_call_historical_whiteouted_copy_shipped():
    first = tar_bytes([("lib/libbrotli.so", b"affected", "file")])
    second = tar_bytes([("lib/.wh.libbrotli.so", b"", "file")])
    image = payloads.oci_filesystems(docker_save({"one.tar": first, "two.tar": second}))[0]
    assert image.members == ()
    add = next(row for row in image.history if row["action"] == "add_or_replace")
    assert add["historical_only"] is True


def test_oci_digest_and_member_budgets_fail_closed():
    layer = tar_bytes([("large", b"1234", "file")])
    archive = docker_save({"layer.tar": layer})
    with pytest.raises(payloads.PayloadError, match="exceeds byte limit"):
        payloads.oci_filesystems(
            archive,
            payloads.PayloadLimits(max_member_bytes=3, max_total_bytes=len(archive) * 2),
        )
    with pytest.raises(payloads.PayloadError, match="cumulative byte limit"):
        payloads.oci_filesystems(
            archive,
            payloads.PayloadLimits(max_member_bytes=len(archive), max_total_bytes=len(archive) - 1),
        )
    with pytest.raises(payloads.PayloadError, match="expanded-byte limit"):
        payloads.apply_oci_layers(
            [("layer", layer, "application/vnd.oci.image.layer.v1.tar")],
            payloads.PayloadLimits(max_member_bytes=100, max_total_bytes=100),
        )


def test_oci_layout_verifies_digests_and_resolves_nested_index():
    layer = tar_bytes([("app/file", b"visible", "file")])
    layer_digest = payloads.hashlib.sha256(layer).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": f"sha256:{layer_digest}",
                    "size": len(layer),
                }
            ],
        }
    ).encode()
    manifest_digest = payloads.hashlib.sha256(manifest).hexdigest()
    nested = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [{"digest": f"sha256:{manifest_digest}", "size": len(manifest)}],
        }
    ).encode()
    nested_digest = payloads.hashlib.sha256(nested).hexdigest()
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [{"digest": f"sha256:{nested_digest}", "size": len(nested)}],
        }
    ).encode()
    archive = tar_bytes(
        [
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}', "file"),
            ("index.json", index, "file"),
            (f"blobs/sha256/{nested_digest}", nested, "file"),
            (f"blobs/sha256/{manifest_digest}", manifest, "file"),
            (f"blobs/sha256/{layer_digest}", layer, "file"),
        ]
    )
    with payloads.open_oci_filesystems(archive) as images:
        assert len(images) == 1
        assert images[0].manifest == f"sha256:{manifest_digest}"
        assert images[0].members[0].read() == b"visible"
