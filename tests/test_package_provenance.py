import base64
import hashlib
import itertools
import json

import brotli_package_provenance as subject
import brotli_payloads
import pytest
from brotli_binary_data import file_data
from test_payloads import cpio_newc, rpm_fixture


def test_dpkg_same_root_ownership_and_exact_md5_binding():
    artifact = b"decoder bytes"
    status = b"""Package: libbrotli1
Status: install ok installed
Architecture: amd64
Version: 1:1.2.1-1ubuntu1

Package: removed
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0
"""
    records = (
        subject.MetadataRecord(
            "/root/var/lib/dpkg/info/libbrotli1:amd64.list",
            b"/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1\n",
        ),
        subject.MetadataRecord(
            "/root/var/lib/dpkg/info/libbrotli1:amd64.md5sums",
            hashlib.md5(artifact, usedforsecurity=False).hexdigest().encode()
            + b"  usr/lib/x86_64-linux-gnu/libbrotlidec.so.1\n",
        ),
    )

    database = subject.parse_dpkg_database(status, records)
    assessment = subject.resolve_ownership(
        "/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1", artifact, database
    )

    assert len(database.packages) == 1
    assert database.gaps == ()
    assert assessment.status == "unique"
    assert assessment.matches[0].package == "libbrotli1"
    assert assessment.matches[0].evidence_strength == "package_file_hash_match"
    assert assessment.matches[0].hash_verified is True

    modified = subject.resolve_ownership(
        "usr/lib/x86_64-linux-gnu/libbrotlidec.so.1", artifact + b"!", database
    )
    assert modified.status == "modified"
    assert modified.matches[0].evidence_strength == "package_id"
    assert any("hash mismatch" in gap for gap in modified.gaps)


def test_dpkg_filedata_metadata_is_sparse_input_compatible(tmp_path):
    status_path = tmp_path / "status"
    status_path.write_bytes(
        b"Package: brotli\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.2.1-1\n"
    )
    with status_path.open("rb") as stream, file_data(stream) as data:
        database = subject.parse_dpkg_database(data, ())
    assert database.packages[0].version == "1.2.1-1"


def test_apk_installed_paths_checksums_and_revisions():
    artifact = b"apk decoder"
    checksum = (
        "Q1" + base64.b64encode(hashlib.sha1(artifact, usedforsecurity=False).digest()).decode()
    )
    installed = f"""P:brotli-libs
V:1.2.1-r2
A:aarch64
F:usr/lib
R:libbrotlidec.so.1
Z:{checksum}

""".encode()

    database = subject.parse_apk_database(installed)
    assessment = subject.resolve_ownership("usr/lib/libbrotlidec.so.1", artifact, database)

    assert database.gaps == ()
    assert database.packages[0].files[0].hashes[0].algorithm == "SHA-1"
    assert assessment.status == "unique"
    assert assessment.matches[0].evidence_strength == "package_file_hash_match"


def test_rpm_metadata_preserves_epoch_and_header_file_digests():
    digest = hashlib.sha256(b"rpm decoder").hexdigest()
    package = subject.package_from_rpm_metadata(
        {
            "name": "brotli",
            "version": "1.2.1",
            "release": "4.el10",
            "epoch": 2,
            "arch": "x86_64",
            "file_digests": [
                {
                    "path": "usr/lib64/libbrotlidec.so.1",
                    "digest": digest,
                    "algorithm": 8,
                }
            ],
        }
    )

    assert package.version == "2:1.2.1-4.el10"
    database = subject.PackageDatabase(packages=(package,), gaps=(), limited=False)
    assessment = subject.resolve_ownership("usr/lib64/libbrotlidec.so.1", b"rpm decoder", database)
    assert assessment.matches[0].evidence_strength == "artifact_hash_bound"

    index = subject.build_ownership_index(database)
    streamed = subject.resolve_ownership_hashes(
        "usr/lib64/libbrotlidec.so.1",
        {"SHA-256": digest},
        database,
        index=index,
    )
    assert index.lookup("usr/lib64/libbrotlidec.so.1")
    assert streamed == assessment


def test_hash_resolver_reports_missing_required_native_digest():
    owned = subject.PackageFile("usr/lib/libbrotli.so", (subject.PackageHash("MD5", "a" * 32),))
    package = subject.PackageRecord("dpkg", "brotli", "1.2.1-1", "amd64", (owned,), "x")
    database = subject.PackageDatabase(packages=(package,), gaps=(), limited=False)

    assessment = subject.resolve_ownership_hashes(
        "usr/lib/libbrotli.so", {"SHA-256": "b" * 64}, database
    )

    assert assessment.status == "unique"
    assert assessment.matches[0].hash_verified is None
    assert any("hash not supplied" in gap for gap in assessment.gaps)


def test_rpm_payload_reader_metadata_feeds_package_ownership_contract():
    payload = brotli_payloads.rpm_payload(rpm_fixture(cpio_newc([])))

    package = subject.package_from_rpm_metadata(payload.metadata)

    assert package.version == "2:1.2.3-4"
    assert package.files == (
        subject.PackageFile("usr/bin/tool", (subject.PackageHash("SHA-256", "a" * 64),)),
    )


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("1.0~rc1-1", "1.0-1"),
        ("1.0-1", "1.0-2"),
        ("0:99-9", "1:1-1"),
        ("1.0", "1.0-1"),
    ],
)
def test_debian_version_boundaries(older, newer):
    assert subject.debian_version_compare(older, newer) < 0
    assert subject.debian_version_compare(newer, older) > 0


def test_debian_numeric_leading_zero_and_revision_zero_equivalence():
    assert subject.debian_version_compare("1.01", "1.1") == 0
    assert subject.debian_version_compare("1.0", "1.0-0") == 0


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("1.0~rc1-1", "1.0-1"),
        ("2.0", "2.0^20260101"),
        ("2.0^20260101", "2.0.1"),
        ("1.0-1", "1.0-2"),
        ("0:99-9", "1:1-1"),
    ],
)
def test_rpm_version_boundaries_tilde_caret_epoch_release(older, newer):
    assert subject.rpm_version_compare(older, newer) < 0
    assert subject.rpm_version_compare(newer, older) > 0


def test_rpm_separators_and_leading_zeroes_are_equivalent():
    assert subject.rpm_version_compare("1.0", "1+0") == 0
    assert subject.rpm_version_compare("1.01", "1.1") == 0


@pytest.mark.parametrize(
    "versions",
    [
        ["1.0_alpha", "1.0_beta", "1.0_pre", "1.0_rc", "1.0"],
        ["1.0", "1.0_cvs", "1.0_svn", "1.0_git", "1.0_hg", "1.0_p"],
        ["1.0-r0", "1.0-r1", "1.0-r2"],
    ],
)
def test_apk_version_suffix_and_revision_order(versions):
    for older, newer in itertools.pairwise(versions):
        assert subject.apk_version_compare(older, newer) < 0
        assert subject.apk_version_compare(newer, older) > 0


def test_apk_invalid_suffix_is_rejected():
    with pytest.raises(ValueError, match="Invalid apk version"):
        subject.apk_version_compare("1.0_unknown", "1.0")


def snapshot(vendor="ubuntu", fixed="1:1.2.1-1ubuntu2"):
    return json.dumps(
        {
            "schema_version": 1,
            "snapshot_date": "2026-10-28",
            "vendor": vendor,
            "release": "24.04" if vendor == "ubuntu" else "10",
            "assertions": [
                {
                    "package": "libbrotli1" if vendor != "redhat" else "brotli",
                    "fixed_version": fixed,
                    "advisory_url": "https://vendor.example/advisory/CVE-2026-111497",
                }
            ],
        }
    )


def test_vendor_snapshot_is_dated_and_version_assertion_is_not_patch_proof():
    loaded = subject.load_vendor_snapshot(snapshot())
    package = subject.PackageRecord(
        "dpkg", "libbrotli1", "1:1.2.1-1ubuntu1", "amd64", (), "fixture"
    )

    assessment = subject.assess_vendor_assertions(package, loaded)[0]

    assert assessment.status == "precedes_vendor_fixed_version"
    assert assessment.patch_status == "unknown"
    fixed_package = subject.PackageRecord(
        "dpkg", "libbrotli1", "1:1.2.1-1ubuntu2", "amd64", (), "fixture"
    )
    assert subject.assess_vendor_assertions(fixed_package, loaded)[0].status == (
        "meets_vendor_fixed_version"
    )


def test_redhat_snapshot_uses_rpm_evr_and_wrong_manager_does_not_cross():
    loaded = subject.load_vendor_snapshot(snapshot("redhat", "2:1.2.1-4.el10"))
    rpm = subject.PackageRecord("rpm", "brotli", "2:1.2.1-4.el10", "x86_64", (), "fixture")
    dpkg = subject.PackageRecord("dpkg", "brotli", "2:1.2.1-4.el10", "amd64", (), "fixture")

    assert subject.assess_vendor_assertions(rpm, loaded)[0].status == ("meets_vendor_fixed_version")
    assert subject.assess_vendor_assertions(dpkg, loaded) == ()


def test_vendor_snapshot_rejects_duplicates_http_and_bad_dates():
    duplicate = json.loads(snapshot())
    duplicate["assertions"].append(dict(duplicate["assertions"][0]))
    with pytest.raises(ValueError, match="Duplicate"):
        subject.load_vendor_snapshot(json.dumps(duplicate))
    insecure = json.loads(snapshot())
    insecure["assertions"][0]["advisory_url"] = "http://vendor.example/advisory"
    with pytest.raises(ValueError, match="assertion value"):
        subject.load_vendor_snapshot(json.dumps(insecure))
    invalid_date = json.loads(snapshot())
    invalid_date["snapshot_date"] = "2026-02-30"
    with pytest.raises(ValueError, match="snapshot date"):
        subject.load_vendor_snapshot(json.dumps(invalid_date))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("vendor", []),
        ("vendor", {}),
        ("vendor", 1),
        ("snapshot_date", []),
        ("release", {}),
        ("assertions", {}),
    ],
)
def test_vendor_snapshot_structured_field_types_fail_closed(field, value):
    malformed = json.loads(snapshot())
    malformed[field] = value
    with pytest.raises(ValueError, match="Invalid vendor snapshot schema"):
        subject.load_vendor_snapshot(json.dumps(malformed))


@pytest.mark.parametrize("algorithm", [[], {}, "8", True])
def test_rpm_digest_algorithm_structured_types_fail_closed(algorithm):
    metadata = {
        "name": "brotli",
        "version": "1.2.1",
        "release": "1",
        "arch": "x86_64",
        "file_digests": [
            {
                "path": "usr/lib64/libbrotlidec.so.1",
                "digest": "a" * 64,
                "algorithm": algorithm,
            }
        ],
    }
    with pytest.raises(ValueError, match="Unsupported RPM file digest"):
        subject.package_from_rpm_metadata(metadata)


def test_ambiguous_and_unowned_package_paths_remain_explicit():
    shared = subject.PackageFile("usr/lib/libbrotli.so")
    database = subject.PackageDatabase(
        packages=(
            subject.PackageRecord("apk", "one", "1-r0", "x86_64", (shared,), "fixture"),
            subject.PackageRecord("apk", "two", "1-r0", "x86_64", (shared,), "fixture"),
        ),
        gaps=(),
        limited=False,
    )

    assert subject.resolve_ownership("usr/lib/libbrotli.so", b"x", database).status == ("ambiguous")
    assert subject.resolve_ownership("usr/lib/other.so", b"x", database).status == "unowned"


@pytest.mark.parametrize(
    "compare", [subject.debian_version_compare, subject.rpm_version_compare], ids=["debian", "rpm"]
)
def test_native_epochs_reject_unicode_digits(compare):
    with pytest.raises(ValueError, match="epoch"):
        compare("\u0661:1.0", "1:1.0")


@pytest.mark.parametrize(
    "version", ["\u0661.0", "1.\u0661", "1.0-r\u0661"], ids=["initial", "component", "revision"]
)
def test_apk_numbers_are_ascii_digits(version):
    # apk-package(5) defines number components as digits 0-9.
    with pytest.raises(ValueError, match="apk version"):
        subject.apk_version_compare(version, "1.0")


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("1.9-1", "1.10-1"),
        ("1.0a-1", "1.0+-1"),
        ("1.0a-1", "1.0b-1"),
        ("1.0-9", "1.0-10"),
    ],
    ids=("numeric-width", "letter-before-punctuation", "letter-order", "revision-width"),
)
def test_debian_version_ordering_uses_native_segment_rules(older, newer):
    assert subject.debian_version_compare(older, newer) == -1
    assert subject.debian_version_compare(newer, older) == 1


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("1.9-1", "1.10-1"),
        ("1a-1", "1b-1"),
        ("1a-1", "1.1-1"),
        ("1.0-9", "1.0-10"),
    ],
    ids=("numeric-width", "letter-order", "numeric-after-alpha", "release-width"),
)
def test_rpm_version_ordering_uses_native_segment_rules(older, newer):
    assert subject.rpm_version_compare(older, newer) == -1
    assert subject.rpm_version_compare(newer, older) == 1


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("1.9", "1.10"),
        ("1.0a", "1.0b"),
        ("1.0~0a", "1.0~0b"),
        ("1.0-r9", "1.0-r10"),
    ],
    ids=("numeric-width", "letter-order", "commit-order", "revision-width"),
)
def test_apk_version_ordering_uses_native_token_rules(older, newer):
    assert subject.apk_version_compare(older, newer) == -1
    assert subject.apk_version_compare(newer, older) == 1


def test_package_metadata_byte_limit_is_inclusive(monkeypatch):
    status = (
        b"Package: brotli\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.2.1-1\n"
    )
    monkeypatch.setattr(subject, "MAX_METADATA_BYTES", len(status))
    assert subject.parse_dpkg_database(status, ()).packages[0].name == "brotli"

    with pytest.raises(ValueError, match="metadata limit"):
        subject.parse_dpkg_database(status + b"\n", ())


def test_dpkg_package_and_file_limits_retain_only_complete_prefix(monkeypatch):
    status = b"""Package: one
Status: install ok installed
Architecture: amd64
Version: 1.0-1

Package: two
Status: install ok installed
Architecture: amd64
Version: 1.0-1
"""
    info = (
        subject.MetadataRecord(
            "/var/lib/dpkg/info/one.list",
            b"/usr/lib/one-a.so\n/usr/lib/one-b.so\n",
        ),
    )
    monkeypatch.setattr(subject, "MAX_PACKAGES", 1)
    monkeypatch.setattr(subject, "MAX_FILES", 1)

    database = subject.parse_dpkg_database(status, info)

    assert [package.name for package in database.packages] == ["one"]
    assert [item.path for item in database.packages[0].files] == ["usr/lib/one-a.so"]
    assert database.limited is True
    assert "Package limit reached" in database.gaps
    assert "Package file limit reached" in database.gaps


def test_rpm_member_limit_and_sha256_length_are_checked_before_binding(monkeypatch):
    metadata = {
        "name": "brotli",
        "version": "1.2.1",
        "release": "1",
        "arch": "x86_64",
        "file_digests": [],
    }
    monkeypatch.setattr(subject, "MAX_FILES", 2)
    package = subject.package_from_rpm_metadata(
        metadata,
        member_paths=("usr/lib/a.so", "usr/lib/b.so"),
        member_sha256={"usr/lib/b.so": "a" * 64},
    )
    assert [item.path for item in package.files] == ["usr/lib/a.so", "usr/lib/b.so"]
    assert package.files[1].hashes == (subject.PackageHash("SHA-256", "a" * 64),)

    with pytest.raises(ValueError, match="path limit"):
        subject.package_from_rpm_metadata(
            metadata,
            member_paths=("usr/lib/a.so", "usr/lib/b.so", "usr/lib/c.so"),
        )
    with pytest.raises(ValueError, match="member SHA-256"):
        subject.package_from_rpm_metadata(
            metadata,
            member_paths=("usr/lib/a.so",),
            member_sha256={"usr/lib/a.so": "a" * 63},
        )


def test_hash_evidence_precedence_keeps_mismatch_and_ambiguity_distinct():
    path = "usr/lib/libbrotli.so"
    actual = hashlib.sha256(b"decoder").hexdigest()
    matching = subject.PackageFile(path, (subject.PackageHash("SHA-256", actual),))
    mismatching = subject.PackageFile(path, (subject.PackageHash("SHA-256", "f" * 64),))
    database = subject.PackageDatabase(
        (
            subject.PackageRecord("rpm", "matching", "1-1", "x86_64", (matching,), "x"),
            subject.PackageRecord("rpm", "modified", "1-1", "x86_64", (mismatching,), "x"),
        ),
        (),
        limited=False,
    )

    assessment = subject.resolve_ownership_hashes(path, {"SHA-256": actual}, database)

    assert assessment.status == "modified"
    assert [item.hash_verified for item in assessment.matches] == [True, False]
    assert [item.evidence_strength for item in assessment.matches] == [
        "artifact_hash_bound",
        "package_id",
    ]
    assert any("hash mismatch" in gap for gap in assessment.gaps)

    both_match = subject.PackageDatabase(
        tuple(
            subject.PackageRecord("rpm", name, "1-1", "x86_64", (matching,), "x")
            for name in ("one", "two")
        ),
        (),
        limited=False,
    )
    assert (
        subject.resolve_ownership_hashes(path, {"SHA-256": actual}, both_match).status
        == "ambiguous"
    )


def test_conflicting_declared_hashes_never_bind_artifact_identity():
    path = "usr/lib/libbrotli.so"
    package_file = subject.PackageFile(
        path,
        (
            subject.PackageHash("SHA-256", "a" * 64),
            subject.PackageHash("SHA-256", "b" * 64),
        ),
    )
    database = subject.PackageDatabase(
        (subject.PackageRecord("rpm", "brotli", "1-1", "x86_64", (package_file,), "x"),),
        (),
        limited=False,
    )

    assessment = subject.resolve_ownership_hashes(path, {"SHA-256": "a" * 64}, database)

    assert assessment.status == "unique"
    assert assessment.matches[0].hash_verified is None
    assert assessment.matches[0].evidence_strength == "package_id"
    assert any("Conflicting package file hashes" in gap for gap in assessment.gaps)


@pytest.mark.parametrize(
    "path",
    ["../host", "usr/lib/../host", "usr/lib/\x7fhost"],
    ids=("parent", "nested-parent", "delete-control"),
)
def test_package_owned_paths_cannot_escape_or_contain_controls(path):
    with pytest.raises(ValueError, match="Invalid package-owned path"):
        subject.resolve_ownership_hashes(path, {}, subject.PackageDatabase((), (), limited=False))
