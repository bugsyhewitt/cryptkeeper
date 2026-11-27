"""Tests for checker.py — certificate and finding analysis."""

import datetime
import pytest
from cryptkeeper.checker import check_certificate, build_findings
from cryptkeeper.payloads import WeaknessFinding


def _make_cert(**overrides) -> dict:
    """Return a minimal valid cert_info dict."""
    base = {
        "subject_cn": "example.com",
        "cert_expiry": (
            datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=365)
        ).isoformat(),
        "cert_self_signed": False,
        "signature_algorithm": "sha256WithRSAEncryption",
    }
    base.update(overrides)
    return base


class TestCheckCertificate:
    def test_valid_cert_no_findings(self):
        result = check_certificate(_make_cert())
        # May have informational findings but no critical/high
        severe = [f for f in result if f.severity in ("critical", "high", "medium")]
        assert len(severe) == 0

    def test_expired_cert_is_critical(self):
        past = (
            datetime.datetime.now(tz=datetime.timezone.utc)
            - datetime.timedelta(days=1)
        ).isoformat()
        result = check_certificate(_make_cert(cert_expiry=past))
        expired = [f for f in result if "expired" in f.detail.lower()]
        assert len(expired) >= 1
        assert expired[0].severity == "critical"

    def test_valid_cert_no_expired_finding(self):
        future = (
            datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=180)
        ).isoformat()
        result = check_certificate(_make_cert(cert_expiry=future))
        expired = [f for f in result if "expired" in f.detail.lower()]
        assert len(expired) == 0

    def test_self_signed_cert_finding(self):
        result = check_certificate(_make_cert(cert_self_signed=True))
        ss = [f for f in result if "self-signed" in f.detail.lower()]
        assert len(ss) >= 1

    def test_sha1_cert_is_high(self):
        result = check_certificate(_make_cert(signature_algorithm="sha1WithRSAEncryption"))
        sha1_findings = [f for f in result if "sha1" in f.detail.lower() or "sha-1" in f.detail.lower() or "sha1" in f.detail]
        assert len(sha1_findings) >= 1
        assert sha1_findings[0].severity == "high"

    def test_sha256_cert_no_sha1_finding(self):
        result = check_certificate(_make_cert(signature_algorithm="sha256WithRSAEncryption"))
        sha1_findings = [f for f in result if "sha1" in f.detail.lower()]
        assert len(sha1_findings) == 0

    def test_returns_list(self):
        result = check_certificate(_make_cert())
        assert isinstance(result, list)

    def test_multiple_issues_multiple_findings(self):
        past = (
            datetime.datetime.now(tz=datetime.timezone.utc)
            - datetime.timedelta(days=1)
        ).isoformat()
        result = check_certificate(
            _make_cert(
                cert_expiry=past,
                cert_self_signed=True,
                signature_algorithm="sha1WithRSAEncryption",
            )
        )
        assert len(result) >= 3

    def test_expiry_within_30_days_is_low(self):
        soon = (
            datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=15)
        ).isoformat()
        result = check_certificate(_make_cert(cert_expiry=soon))
        expiry_warn = [f for f in result if "expires" in f.detail.lower()]
        assert len(expiry_warn) >= 1
        assert expiry_warn[0].severity == "low"


class TestBuildFindings:
    def _make_probe(self, **overrides) -> dict:
        base = {
            "protocol": "TLSv1.2",
            "cipher_name": "ECDHE-RSA-AES256-GCM-SHA384",
            "cipher_bits": 256,
            "cert_expiry": (
                datetime.datetime.now(tz=datetime.timezone.utc)
                + datetime.timedelta(days=365)
            ).isoformat(),
            "cert_self_signed": False,
            "signature_algorithm": "sha256WithRSAEncryption",
            "subject_cn": "example.com",
            "supports_tls10": False,
            "supports_tls11": False,
            "supports_sslv3": False,
        }
        base.update(overrides)
        return base

    def test_clean_probe_no_critical_findings(self):
        result = build_findings("example.com:443", self._make_probe())
        critical = [f for f in result if f.severity == "critical"]
        assert len(critical) == 0

    def test_weak_cipher_generates_finding(self):
        result = build_findings("example.com:443", self._make_probe(cipher_name="RC4-SHA"))
        cipher_findings = [f for f in result if f.category == "cipher"]
        assert len(cipher_findings) >= 1

    def test_tls10_support_generates_finding(self):
        result = build_findings("example.com:443", self._make_probe(supports_tls10=True))
        proto_findings = [f for f in result if f.category == "protocol"]
        assert len(proto_findings) >= 1
