import hashlib
import json
import sys
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import brotli_sigstore as subject
import pytest

DIGEST = "a" * 64
IDENTITY = "https://github.com/example/project/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"


def policy(**updates):
    value = {
        "schema_version": 1,
        "certificate_identity": IDENTITY,
        "certificate_oidc_issuer": ISSUER,
        "evaluation_time": "2026-11-02T12:00:00Z",
        "trust_config_expires_at": "2026-11-03T00:00:00Z",
        "max_signature_age_seconds": 3600,
        "max_future_skew_seconds": 60,
    }
    value.update(updates)
    return json.dumps(value).encode()


def bundle(integrated=1793620500):
    return json.dumps(
        {"verificationMaterial": {"tlogEntries": [{"integratedTime": str(integrated)}]}}
    ).encode()


def success(command, timeout, max_output):
    assert timeout == subject.TOOL_TIMEOUT_SECONDS
    assert max_output == subject.MAX_TOOL_OUTPUT_BYTES
    assert command[0] == str(Path(sys.executable).resolve())
    if command[1:] == ["--version"]:
        return {
            "returncode": 0,
            "output": subject.EXPECTED_SIGSTORE_VERSION + "\n",
            "limited": False,
            "reason": None,
        }
    assert command[1] == "--trust-config"
    assert command[3:7] == ["verify", "identity", "--bundle", command[6]]
    assert "--offline" in command
    assert command[-5:] == [
        "--cert-identity",
        IDENTITY,
        "--cert-oidc-issuer",
        ISSUER,
        f"sha256:{DIGEST}",
    ]
    assert Path(command[2]).read_bytes() == b'{"trusted":true}'
    assert json.loads(Path(command[6]).read_bytes())["verificationMaterial"]["tlogEntries"]
    return {"returncode": 0, "output": "OK\n", "limited": False, "reason": None}


def test_external_sigstore_verifier_gets_only_captured_inputs_and_exact_digest(monkeypatch):
    monkeypatch.setattr(subject, "run_bounded", success)
    raw_policy = policy()
    result = subject.verify_sigstore_bundle(
        bundle(),
        b'{"trusted":true}',
        raw_policy,
        artifact_sha256=DIGEST,
        verifier_path=Path(sys.executable),
    )
    assert result["signature_status"] == "verified"
    assert result["subject_sha256"] == [DIGEST]
    assert result["trust_config_sha256"] == hashlib.sha256(b'{"trusted":true}').hexdigest()
    assert result["policy_sha256"] == hashlib.sha256(raw_policy).hexdigest()
    assert result["freshness"]["status"] == "verified_within_local_policy_window"
    assert result["patch_status"] == "unknown"


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"certificate_identity": ""}, "identity and issuer"),
        ({"trust_config_expires_at": "2026-11-01T00:00:00Z"}, "stale"),
        ({"max_signature_age_seconds": -1}, "maximum signature age"),
        ({"max_future_skew_seconds": 86401}, "future skew"),
        ({"evaluation_time": "now"}, "RFC3339 UTC"),
        ({"schema_version": True}, "policy schema"),
        ({"certificate_identity": 1}, "identity and issuer"),
    ],
)
def test_sigstore_policy_is_explicit_and_bounded(updates, message):
    with pytest.raises(ValueError, match=message):
        subject.load_sigstore_policy(policy(**updates))


@pytest.mark.parametrize(
    ("integrated", "message"),
    [
        (1793610000, "allowed age"),
        (1793620861, "future skew"),
        (-1, "integrated time"),
    ],
)
def test_sigstore_freshness_fails_closed(monkeypatch, integrated, message):
    monkeypatch.setattr(subject, "run_bounded", success)
    with pytest.raises(ValueError, match=message):
        subject.verify_sigstore_bundle(
            bundle(integrated),
            b'{"trusted":true}',
            policy(),
            artifact_sha256=DIGEST,
            verifier_path=Path(sys.executable),
        )


def test_sigstore_tool_failure_and_limits_are_not_success(monkeypatch):
    def failed(command, *_):
        if command[1:] == ["--version"]:
            return {
                "returncode": 0,
                "output": subject.EXPECTED_SIGSTORE_VERSION + "\n",
                "limited": False,
                "reason": None,
            }
        return {"returncode": 1, "output": "bad proof", "limited": False, "reason": None}

    monkeypatch.setattr(subject, "run_bounded", failed)
    with pytest.raises(ValueError, match=r"failed \(1\): bad proof"):
        subject.verify_sigstore_bundle(
            bundle(),
            b'{"trusted":true}',
            policy(),
            artifact_sha256=DIGEST,
            verifier_path=Path(sys.executable),
        )

    def limited(command, *_):
        if command[1:] == ["--version"]:
            return {
                "returncode": 0,
                "output": subject.EXPECTED_SIGSTORE_VERSION + "\n",
                "limited": False,
                "reason": None,
            }
        return {"returncode": None, "output": "", "limited": True, "reason": "timeout"}

    monkeypatch.setattr(subject, "run_bounded", limited)
    with pytest.raises(ValueError, match="incomplete: timeout"):
        subject.verify_sigstore_bundle(
            bundle(),
            b"{}",
            policy(),
            artifact_sha256=DIGEST,
            verifier_path=Path(sys.executable),
        )


def test_sigstore_requires_absolute_executable_and_exact_digest(monkeypatch):
    monkeypatch.setattr(subject, "run_bounded", success)
    with pytest.raises(ValueError, match="absolute"):
        subject.verify_sigstore_bundle(
            bundle(),
            b"{}",
            policy(),
            artifact_sha256=DIGEST,
            verifier_path=Path("sigstore"),
        )
    with pytest.raises(ValueError, match="exact SHA-256"):
        subject.verify_sigstore_bundle(
            bundle(),
            b"{}",
            policy(),
            artifact_sha256="A" * 64,
            verifier_path=Path(sys.executable),
        )


def test_sigstore_bundle_time_population_must_be_present_and_valid(monkeypatch):
    monkeypatch.setattr(
        subject,
        "run_bounded",
        success,
    )
    raw = json.dumps({"verificationMaterial": {"tlogEntries": []}}).encode()
    with pytest.raises(ValueError, match="requires a transparency-log"):
        subject.verify_sigstore_bundle(
            raw,
            b'{"trusted":true}',
            policy(),
            artifact_sha256=DIGEST,
            verifier_path=Path(sys.executable),
        )


def test_sigstore_rejects_unqualified_verifier_version(monkeypatch):
    monkeypatch.setattr(
        subject,
        "run_bounded",
        lambda *_: {
            "returncode": 0,
            "output": "sigstore 4.1.0\n",
            "limited": False,
            "reason": None,
        },
    )
    with pytest.raises(ValueError, match="Unqualified Sigstore verifier version"):
        subject.verify_sigstore_bundle(
            bundle(),
            b"{}",
            policy(),
            artifact_sha256=DIGEST,
            verifier_path=Path(sys.executable),
        )


def test_sigstore_policy_is_immutable_and_accepts_exact_time_boundaries():
    evaluated = datetime(2026, 11, 2, 12, tzinfo=UTC)
    value = subject.SigstorePolicy(
        IDENTITY,
        ISSUER,
        evaluated,
        evaluated,
        subject.MAX_FRESHNESS_SECONDS,
        24 * 60 * 60,
    )
    with pytest.raises(FrozenInstanceError):
        cast("Any", value).certificate_identity = "changed"
    assert (
        subject._check_freshness(  # noqa: SLF001
            [int((evaluated - timedelta(seconds=subject.MAX_FRESHNESS_SECONDS)).timestamp())],
            value,
        )["status"]
        == "verified_within_local_policy_window"
    )
    assert (
        subject._check_freshness(  # noqa: SLF001
            [int((evaluated + timedelta(seconds=24 * 60 * 60)).timestamp())],
            value,
        )["status"]
        == "verified_within_local_policy_window"
    )

    with pytest.raises(ValueError, match="maximum signature age"):
        subject.SigstorePolicy(
            IDENTITY,
            ISSUER,
            evaluated,
            evaluated,
            subject.MAX_FRESHNESS_SECONDS + 1,
            0,
        )
    with pytest.raises(ValueError, match="future skew"):
        subject.SigstorePolicy(
            IDENTITY,
            ISSUER,
            evaluated,
            evaluated,
            0,
            24 * 60 * 60 + 1,
        )


@pytest.mark.parametrize("field", ["evaluation_time", "trust_config_expires_at"])
def test_sigstore_programmatic_policy_rejects_each_naive_time(field):
    values = {
        "certificate_identity": IDENTITY,
        "certificate_oidc_issuer": ISSUER,
        "evaluation_time": datetime(2026, 11, 2, tzinfo=UTC),
        "trust_config_expires_at": datetime(2026, 11, 3, tzinfo=UTC),
        "max_signature_age_seconds": 0,
        "max_future_skew_seconds": 0,
    }
    values[field] = values[field].replace(tzinfo=None)
    with pytest.raises(ValueError, match="timezone-aware"):
        subject.SigstorePolicy(**values)


def test_integrated_time_shape_and_canonical_forms_are_independent():
    assert subject._integrated_times(  # noqa: SLF001
        {"verificationMaterial": {"tlogEntries": [{"integratedTime": 0}, {"integratedTime": "1"}]}}
    ) == (0, 1)
    for entry in (None, {"integratedTime": True}, {"integratedTime": "\uff11\uff12"}):
        with pytest.raises(ValueError, match="integrated time"):
            subject._integrated_times(  # noqa: SLF001
                {"verificationMaterial": {"tlogEntries": [entry]}}
            )


def test_sigstore_verifier_identity_failures_are_distinct(monkeypatch):
    monkeypatch.setattr(
        subject,
        "run_bounded",
        lambda *_: {"returncode": None, "output": "", "limited": True, "reason": "timeout"},
    )
    with pytest.raises(ValueError, match="Cannot identify"):
        subject.verify_sigstore_bundle(
            bundle(), b"{}", policy(), artifact_sha256=DIGEST, verifier_path=Path(sys.executable)
        )
    monkeypatch.setattr(
        subject,
        "run_bounded",
        lambda *_: {"returncode": 1, "output": "bad", "limited": False, "reason": None},
    )
    with pytest.raises(ValueError, match="Cannot identify"):
        subject.verify_sigstore_bundle(
            bundle(), b"{}", policy(), artifact_sha256=DIGEST, verifier_path=Path(sys.executable)
        )


def test_sigstore_verifier_must_remain_identical(monkeypatch):
    monkeypatch.setattr(subject, "run_bounded", success)
    identities = iter(("a" * 64, "b" * 64))
    monkeypatch.setattr(subject, "_file_sha256", lambda _: next(identities))
    with pytest.raises(ValueError, match="changed during verification"):
        subject.verify_sigstore_bundle(
            bundle(),
            b'{"trusted":true}',
            policy(),
            artifact_sha256=DIGEST,
            verifier_path=Path(sys.executable),
        )


def test_sigstore_verifier_path_requires_executable_regular_file(tmp_path):
    verifier = tmp_path / "verifier"
    verifier.write_text("not executable")
    with pytest.raises(ValueError, match="executable regular"):
        subject._trusted_executable(verifier)  # noqa: SLF001
    with pytest.raises(ValueError, match="executable regular"):
        subject._trusted_executable(tmp_path)  # noqa: SLF001
