import gzip
import io
import json
import stat
import struct
import tarfile
from dataclasses import FrozenInstanceError
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


def test_payload_limits_subranges_and_names_enforce_exact_boundaries():
    with pytest.raises(ValueError, match="nonnegative"):
        payloads.PayloadLimits(max_members=-1)
    with pytest.raises(payloads.PayloadError, match="outside input"):
        payloads.SubrangeStream(b"abc", 2, 2)
    probe = payloads.SubrangeStream(b"012345", 1, 3)
    assert probe.seek(1) == 1
    target = bytearray(b"xxxxx")
    assert probe.readinto(target) == 2
    assert len(target) == 5
    assert target == b"23xxx"
    stream = payloads.SubrangeStream(b"012345", 1, 3)
    assert stream.readable()
    assert stream.seekable()
    assert stream.tell() == 0
    assert stream.read(2) == b"12"
    assert stream.seek(-1, io.SEEK_CUR) == 1
    assert stream.read() == b"23"
    assert stream.seek(-1, io.SEEK_END) == 2
    assert stream.read() == b"3"
    with pytest.raises(ValueError, match="whence"):
        stream.seek(0, 99)
    with pytest.raises(OSError, match="negative"):
        stream.seek(-1)
    stream.close()
    with pytest.raises(ValueError, match="closed"):
        stream.read(1)
    for unsafe in ("", "/absolute", "../parent", "control\nname", "x" * 4097):
        with pytest.raises(payloads.PayloadError):
            payloads._safe_name(unsafe)  # noqa: SLF001 -- Direct defensive boundary.
    with pytest.raises(payloads.PayloadError, match="range outside"):
        payloads._checked(b"abc", 2, 2)  # noqa: SLF001 -- Direct range boundary.


def test_payload_evidence_objects_are_immutable_and_stream_views_do_not_copy():
    limits = payloads.PayloadLimits(1, 2, 3)
    member = payloads.PayloadMember("file", 2, b"xabc", 1, metadata={"origin": "fixture"})
    image = payloads.OciFilesystem((member,), (), (), "fixture")
    rpm = payloads.RpmPayload({"name": "fixture"}, "none", member)
    for value, field in (
        (limits, "max_members"),
        (member, "size"),
        (image, "manifest"),
        (rpm, "compressor"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(value, field, None)
    with member.open() as stream:
        assert isinstance(stream, payloads.SubrangeStream)
        assert stream.read() == b"ab"
    assert member.read() == b"ab"
    assert member.metadata == {"origin": "fixture"}


@pytest.mark.parametrize("field", ["max_members", "max_member_bytes", "max_total_bytes"])
def test_each_payload_limit_rejects_negative_values(field):
    values = {"max_members": 1, "max_member_bytes": 1, "max_total_bytes": 1}
    values[field] = -1
    with pytest.raises(ValueError, match="nonnegative"):
        payloads.PayloadLimits(**values)


@pytest.mark.parametrize("value", [True, 1.0, "1"], ids=["boolean", "float", "string"])
def test_payload_limits_require_exact_integers(value):
    with pytest.raises(ValueError, match="nonnegative"):
        payloads.PayloadLimits(max_members=value)


def test_subrange_seek_clamps_past_end_and_readinto_preserves_unused_bytes():
    stream = payloads.SubrangeStream(b"abcdef", 1, 3)
    assert stream.seek(100) == 3
    target = bytearray(b"unchanged")
    assert stream.readinto(target) == 0
    assert target == b"unchanged"
    assert stream.seek(0) == 0
    target = bytearray(b".....")
    assert stream.readinto(target) == 3
    assert target == b"bcd.."
    assert stream.tell() == 3


@pytest.mark.parametrize(
    ("offset", "size"),
    [(0, 0), (0, 3), (3, 0)],
    ids=("empty-start", "whole-input", "empty-end"),
)
def test_subrange_and_checked_ranges_accept_every_exact_endpoint(offset, size):
    stream = payloads.SubrangeStream(b"abc", offset, size)
    # Validate raw counts before RawIOBase.read() passes them to CPython's C buffer.
    expected = b"abc"[offset : offset + size]
    target = bytearray(b"." * (size + 1))
    assert stream.readinto(target) == size
    assert len(target) == size + 1
    assert target == expected + b"."
    assert stream.readinto(bytearray(1)) == 0
    assert stream.seek(0) == 0
    assert stream.read() == expected
    assert payloads._checked(b"abc", offset, size) == b"abc"[offset : offset + size]  # noqa: SLF001


@pytest.mark.parametrize(
    ("offset", "size"),
    [(-1, 0), (0, -1), (4, 0), (3, 1), (1, 3)],
    ids=("negative-offset", "negative-size", "offset-past-end", "start-at-end", "cross-end"),
)
def test_subrange_and_checked_ranges_reject_each_outside_dimension(offset, size):
    with pytest.raises(payloads.PayloadError, match="outside input"):
        payloads.SubrangeStream(b"abc", offset, size)
    with pytest.raises(payloads.PayloadError, match="outside input"):
        payloads._checked(b"abc", offset, size)  # noqa: SLF001


def test_payload_names_accept_exact_limit_and_normalize_only_safe_segments():
    assert payloads._safe_name("x" * payloads.MAX_NAME_BYTES) == "x" * payloads.MAX_NAME_BYTES  # noqa: SLF001
    assert payloads._safe_name("./dir\\file") == "dir/file"  # noqa: SLF001
    assert payloads._safe_name("control\x80") == "control\x80"  # noqa: SLF001
    for value in ("control\x1f", "control\x7f"):
        with pytest.raises(payloads.PayloadError, match="control"):
            payloads._safe_name(value)  # noqa: SLF001


def test_expanded_stream_limit_accepts_exact_bytes_and_rejects_first_extra_byte():
    exact = payloads._ExpandedLimitStream(io.BytesIO(b"abc"), 3)  # noqa: SLF001
    target = bytearray(3)
    assert exact.readinto(target) == 3
    assert target == b"abc"
    assert exact.readinto(target) == 0
    overflow = payloads._ExpandedLimitStream(io.BytesIO(b"abcd"), 3)  # noqa: SLF001
    with pytest.raises(payloads.PayloadError, match="expanded-byte limit"):
        overflow.readinto(bytearray(4))


def test_bounded_member_total_is_independent_of_per_member_limit():
    members = iter(
        [
            payloads.PayloadMember("a", 3, b"aaa"),
            payloads.PayloadMember("b", 3, b"bbb"),
        ]
    )
    with pytest.raises(payloads.PayloadError, match="cumulative"):
        list(
            payloads._bounded_members(  # noqa: SLF001 -- Direct aggregate-limit contract.
                members,
                payloads.PayloadLimits(max_members=2, max_member_bytes=3, max_total_bytes=5),
            )
        )


def test_bounded_member_limits_accept_exact_population_and_reject_each_overflow():
    exact = [payloads.PayloadMember("a", 2, b"aa"), payloads.PayloadMember("b", 3, b"bbb")]
    limits = payloads.PayloadLimits(max_members=2, max_member_bytes=3, max_total_bytes=5)
    assert list(payloads._bounded_members(iter(exact), limits)) == exact  # noqa: SLF001
    with pytest.raises(payloads.PayloadError, match="member count"):
        list(payloads._bounded_members(iter([*exact, exact[0]]), limits))  # noqa: SLF001
    with pytest.raises(payloads.PayloadError, match="member exceeds"):
        list(
            payloads._bounded_members(  # noqa: SLF001
                iter([payloads.PayloadMember("large", 4, b"xxxx")]), limits
            )
        )


def test_payload_kind_and_dispatch_cover_each_supported_member_family():
    cpio = cpio_newc([("file", b"x", stat.S_IFREG | 0o600)])
    ar = ar_archive(("file/", b"x"))
    deb = ar_archive(("debian-binary/", b"2.0\n"), ("data.tar/", b"x"))
    assert payloads.payload_kind(ar) == "ar"
    assert payloads.payload_kind(deb) == "deb"
    assert payloads.payload_kind(payloads.RPM_MAGIC + bytes(100)) == "rpm"
    assert payloads.payload_kind(payloads.ZSTD_MAGIC + bytes(4)) == "zstd"
    assert payloads.payload_kind(cpio) == "cpio"
    assert payloads.payload_kind(b"opaque", "image.oci") == "oci"
    assert payloads.payload_kind(b"opaque") is None
    assert next(payloads.iter_payload_members(ar, "ar")).read() == b"x"
    assert next(payloads.iter_payload_members(deb, "deb")).name == "data.tar"
    assert next(payloads.iter_payload_members(cpio, "cpio")).read() == b"x"
    with pytest.raises(payloads.PayloadError, match="unsupported payload kind"):
        next(payloads.iter_payload_members(b"opaque", "unknown"))


def test_oci_probe_does_not_apply_oci_name_rules_to_ordinary_tar():
    ordinary = tar_bytes([("hostile\nname", b"data", "file")])
    assert not payloads.oci_archive_candidate(ordinary)
    image = docker_save({"layer/layer.tar": tar_bytes([("app/file", b"data", "file")])})
    assert payloads.oci_archive_candidate(image)


def test_oci_probe_limits_and_malformed_tar_are_fail_closed():
    many = tar_bytes([("first", b"a", "file"), ("manifest.json", b"[]", "file")])
    assert not payloads.oci_archive_candidate(many, payloads.PayloadLimits(max_members=1))
    with pytest.raises(payloads.PayloadError, match="cannot inspect tar"):
        payloads.oci_archive_candidate(b"not a tar archive")


def test_oci_probe_requires_complete_root_marker_pair_and_honors_first_member_limit():
    index_only = tar_bytes([("index.json", b'{"manifests":[]}', "file")])
    layout_only = tar_bytes([("oci-layout", b'{"imageLayoutVersion":"1.0.0"}', "file")])
    assert payloads.oci_archive_candidate(index_only) is False
    assert payloads.oci_archive_candidate(layout_only) is False
    marker_first = tar_bytes([("manifest.json", b"[]", "file"), ("later", b"x", "file")])
    assert (
        payloads.oci_archive_candidate(marker_first, payloads.PayloadLimits(max_members=1)) is True
    )


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


def test_ar_extended_names_symbol_tables_and_alignment_are_validated():
    bad_bsd = payloads.AR_MAGIC + ar_member("#1/not-a-size", b"data")
    with pytest.raises(payloads.PayloadError, match="BSD ar extended"):
        list(payloads.iter_ar_members(bad_bsd))
    unterminated = payloads.AR_MAGIC + ar_member("//", b"long-name") + ar_member("/0", b"x")
    with pytest.raises(payloads.PayloadError, match="unterminated GNU"):
        list(payloads.iter_ar_members(unterminated))
    symbols = payloads.AR_MAGIC + ar_member("/", b"index") + ar_member("real/", b"data")
    assert [member.name for member in payloads.iter_ar_members(symbols)] == ["real"]
    truncated_padding = ar_archive(("odd/", b"x"))[:-1]
    with pytest.raises(payloads.PayloadError, match="alignment"):
        list(payloads.iter_ar_members(truncated_padding))
    with pytest.raises(payloads.PayloadError, match="empty Debian"):
        list(payloads.iter_deb_members(payloads.AR_MAGIC))


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


def test_cpio_names_trailers_and_member_types_fail_closed():
    archive = cpio_newc([("device", b"", stat.S_IFCHR | 0o600)])
    assert next(payloads.iter_cpio_members(archive)).kind == "other"
    missing_trailer = cpio_newc([("file", b"x", stat.S_IFREG | 0o600)])[:-124]
    with pytest.raises(payloads.PayloadError, match="lacks TRAILER"):
        list(payloads.iter_cpio_members(missing_trailer))
    unterminated = bytearray(cpio_newc([("file", b"x", stat.S_IFREG | 0o600)]))
    unterminated[114] = ord("x")
    with pytest.raises(payloads.PayloadError, match="lacks terminator"):
        list(payloads.iter_cpio_members(bytes(unterminated)))
    longest = "x" * payloads.MAX_NAME_BYTES
    assert (
        next(payloads.iter_cpio_members(cpio_newc([(longest, b"", stat.S_IFREG | 0o600)]))).name
        == longest
    )
    with pytest.raises(payloads.PayloadError, match="name size"):
        list(
            payloads.iter_cpio_members(
                cpio_newc([("x" * (payloads.MAX_NAME_BYTES + 1), b"", stat.S_IFREG | 0o600)])
            )
        )


def test_bounded_expanded_reader_accepts_exact_limit_and_rejects_first_extra_byte():
    assert payloads._read_all_bounded(io.BytesIO(b"abc"), 3) == b"abc"  # noqa: SLF001
    with pytest.raises(payloads.PayloadError, match="exceeds 2-byte limit"):
        payloads._read_all_bounded(io.BytesIO(b"abc"), 2)  # noqa: SLF001


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


def test_rpm_header_alignment_uniqueness_and_lengths_are_validated():
    lead = bytes(bytearray(payloads.RPM_MAGIC + bytes(92)))
    duplicate = lead + rpm_header([(1000, "one"), (1000, "two")])
    with pytest.raises(payloads.PayloadError, match="duplicate RPM"):
        payloads.rpm_payload(duplicate)
    misaligned_header = bytearray(rpm_header([(1003, [2])]))
    struct.pack_into(">I", misaligned_header, 16 + 8, 1)
    with pytest.raises(payloads.PayloadError, match="misaligned"):
        payloads.rpm_payload(lead + bytes(misaligned_header))
    unterminated_header = rpm_header([(1000, "name")])[:-1] + b"x"
    with pytest.raises(payloads.PayloadError, match="unterminated"):
        payloads.rpm_payload(lead + unterminated_header)
    truncated_integer = bytearray(rpm_header([(1003, [2])]))
    struct.pack_into(">I", truncated_integer, 16 + 12, 2)
    with pytest.raises(payloads.PayloadError, match="truncated RPM integer"):
        payloads.rpm_payload(lead + bytes(truncated_integer))


def test_rpm_header_binary_values_and_exact_string_limit_are_preserved(monkeypatch):
    binary = (
        b"\x8e\xad\xe8\x01"
        + bytes(4)
        + struct.pack(">II", 1, 2)
        + struct.pack(">IIII", 5099, 7, 0, 2)
        + b"\x00\xff"
    )
    values, end = payloads._rpm_header(binary, 0)  # noqa: SLF001 -- Exact RPM tag decoding.
    assert values[5099] == b"\x00\xff"
    assert end == len(binary)
    monkeypatch.setattr(payloads, "MAX_NAME_BYTES", 4)
    exact = rpm_header([(1000, "abcd")])
    assert payloads._rpm_header(exact, 0)[0][1000] == "abcd"  # noqa: SLF001
    with pytest.raises(payloads.PayloadError, match="unterminated"):
        payloads._rpm_header(rpm_header([(1000, "abcde")]), 0)  # noqa: SLF001


def test_missing_rpm_digest_populations_are_not_fabricated():
    assert payloads._rpm_file_digests({}, 8) == []  # noqa: SLF001
    assert (
        payloads._rpm_file_digests(  # noqa: SLF001
            {1117: ["tool"], 1118: ["/usr/bin/"], 1116: [0], 1035: [""]}, 8
        )
        == []
    )


def test_rpm_file_digest_arrays_require_one_bounded_path_per_digest():
    with pytest.raises(payloads.PayloadError, match="inconsistent lengths"):
        payloads._rpm_file_digests(  # noqa: SLF001 -- Header-array ownership boundary.
            {1117: ["tool"], 1118: ["/usr/bin/"], 1116: [0], 1035: []}, 8
        )
    with pytest.raises(payloads.PayloadError, match="invalid RPM per-file"):
        payloads._rpm_file_digests(  # noqa: SLF001 -- Header-array ownership boundary.
            {1117: ["tool"], 1118: ["/usr/bin/"], 1116: [1], 1035: ["a" * 64]}, 8
        )


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


def test_production_oci_metadata_and_outer_tar_bounds_are_explicit(monkeypatch):
    invalid_json = tar_bytes([("manifest.json", b"not json", "file")])
    with (
        pytest.raises(payloads.PayloadError, match="invalid OCI JSON"),
        payloads.open_oci_filesystems(invalid_json),
    ):
        pass
    monkeypatch.setattr(payloads, "MAX_METADATA_BYTES", 2)
    oversized_json = tar_bytes([("manifest.json", b"[ ]", "file")])
    with (
        pytest.raises(payloads.PayloadError, match="metadata exceeds"),
        payloads.open_oci_filesystems(oversized_json),
    ):
        pass
    nonregular = tar_bytes([("manifest.json", b"target", "symlink")])
    with (
        pytest.raises(payloads.PayloadError, match="nonregular"),
        payloads.open_oci_filesystems(nonregular),
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


def test_oci_layout_version_duplicate_descriptors_and_layers_fail_closed():
    empty_manifest = json.dumps({"schemaVersion": 2, "layers": []}).encode()
    digest = payloads.hashlib.sha256(empty_manifest).hexdigest()
    duplicate_index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [
                {"digest": f"sha256:{digest}", "size": len(empty_manifest)},
                {"digest": f"sha256:{digest}", "size": len(empty_manifest)},
            ],
        }
    ).encode()
    archive = tar_bytes(
        [
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}', "file"),
            ("index.json", duplicate_index, "file"),
            (f"blobs/sha256/{digest}", empty_manifest, "file"),
        ]
    )
    with (
        pytest.raises(payloads.PayloadError, match="duplicate OCI"),
        payloads.open_oci_filesystems(archive),
    ):
        pass
    bad_version = tar_bytes(
        [
            ("oci-layout", b'{"imageLayoutVersion":"2.0.0"}', "file"),
            ("index.json", b'{"manifests":[]}', "file"),
        ]
    )
    with (
        pytest.raises(payloads.PayloadError, match="image-layout version"),
        payloads.open_oci_filesystems(bad_version),
    ):
        pass
    layer_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "layers": [
                {
                    "mediaType": "application/unsupported",
                    "digest": "sha256:" + "0" * 64,
                    "size": 1,
                }
            ],
        }
    ).encode()
    manifest_digest = payloads.hashlib.sha256(layer_manifest).hexdigest()
    bad_layer = tar_bytes(
        [
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}', "file"),
            (
                "index.json",
                json.dumps(
                    {
                        "manifests": [
                            {
                                "digest": f"sha256:{manifest_digest}",
                                "size": len(layer_manifest),
                            }
                        ]
                    }
                ).encode(),
                "file",
            ),
            (f"blobs/sha256/{manifest_digest}", layer_manifest, "file"),
        ]
    )
    with (
        pytest.raises(payloads.PayloadError, match="layer blob missing or digest unsupported"),
        payloads.open_oci_filesystems(bad_layer),
    ):
        pass


def test_subrange_reports_actual_copied_bytes_on_short_source_reads():
    class ShortReads(bytes):
        def __getitem__(self, key):
            result = super().__getitem__(key)
            return result[:1] if isinstance(key, slice) else result

    stream = payloads.SubrangeStream(ShortReads(b"abc"), 0, 3)
    target = bytearray(b"....")
    assert stream.readinto(target) == 1
    assert target == b"a..."
    assert stream.tell() == 1
    assert stream.readinto(target) == 1
    assert target == b"b..."
    assert stream.tell() == 2
    assert stream.readinto(target) == 1
    assert target == b"c..."
    assert stream.tell() == 3
    assert stream.readinto(target) == 0
    assert target == b"c..."
