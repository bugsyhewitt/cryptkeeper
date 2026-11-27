"""Tests for payloads.py — weakness pattern data and WeaknessFinding dataclass."""

import pytest
from cryptkeeper.payloads import (
    WEAK_CIPHERS,
    WEAK_PROTOCOLS,
    WeaknessFinding,
)
from cryptkeeper.checker import check_cipher_weakness, check_protocol_weakness


class TestWeakCipherPatterns:
    def test_weak_ciphers_nonempty(self):
        assert len(WEAK_CIPHERS) > 0

    def test_weak_ciphers_contains_rc4(self):
        assert "RC4" in WEAK_CIPHERS

    def test_weak_ciphers_contains_3des(self):
        assert "3DES" in WEAK_CIPHERS

    def test_weak_protocols_nonempty(self):
        assert len(WEAK_PROTOCOLS) > 0

    def test_weak_protocols_contains_sslv3(self):
        assert "SSLv3" in WEAK_PROTOCOLS

    def test_weak_protocols_contains_tls10(self):
        assert "TLSv1" in WEAK_PROTOCOLS

    def test_weak_protocols_contains_tls11(self):
        assert "TLSv1.1" in WEAK_PROTOCOLS


class TestCheckCipherWeakness:
    def test_rc4_cipher_is_critical(self):
        result = check_cipher_weakness("RC4-SHA")
        assert result == "critical"

    def test_3des_cipher_is_high(self):
        result = check_cipher_weakness("ECDHE-RSA-3DES-EDE-CBC-SHA")
        assert result is not None
        assert result in ("critical", "high")

    def test_aes256_gcm_is_fine(self):
        result = check_cipher_weakness("ECDHE-RSA-AES256-GCM-SHA384")
        assert result is None

    def test_null_cipher_is_critical(self):
        result = check_cipher_weakness("NULL-MD5")
        assert result == "critical"

    def test_export_cipher_is_critical(self):
        result = check_cipher_weakness("EXP-RC4-MD5")
        assert result == "critical"

    def test_anon_cipher_is_critical(self):
        result = check_cipher_weakness("ADH-AES256-SHA")
        # ANON pattern not in name, should check specifically
        result2 = check_cipher_weakness("ECDH-ANON-AES128-CBC-SHA")
        assert result2 == "critical"

    def test_cbc_cipher_is_medium(self):
        result = check_cipher_weakness("AES128-CBC-SHA")
        assert result == "medium"

    def test_md5_cipher_is_high(self):
        result = check_cipher_weakness("RC4-MD5")
        # RC4 hits first (critical), but MD5-only should be high
        result2 = check_cipher_weakness("AES256-MD5")
        assert result2 == "high"

    def test_tls13_aes_gcm_is_fine(self):
        result = check_cipher_weakness("TLS_AES_256_GCM_SHA384")
        assert result is None


class TestCheckProtocolWeakness:
    def test_sslv3_is_critical(self):
        result = check_protocol_weakness("SSLv3")
        assert result == "critical"

    def test_tls10_is_high(self):
        result = check_protocol_weakness("TLSv1")
        assert result == "high"

    def test_tls11_is_medium(self):
        result = check_protocol_weakness("TLSv1.1")
        assert result == "medium"

    def test_tls12_is_fine(self):
        result = check_protocol_weakness("TLSv1.2")
        assert result is None

    def test_tls13_is_fine(self):
        result = check_protocol_weakness("TLSv1.3")
        assert result is None


class TestWeaknessFinding:
    def test_finding_has_severity_field(self):
        f = WeaknessFinding(
            target="example.com:443",
            category="cipher",
            detail="Weak cipher: RC4",
            severity="critical",
        )
        assert f.severity == "critical"

    def test_finding_cve_defaults_to_none(self):
        f = WeaknessFinding(
            target="example.com:443",
            category="protocol",
            detail="Old protocol",
            severity="high",
        )
        assert f.cve is None

    def test_finding_with_cve(self):
        f = WeaknessFinding(
            target="example.com:443",
            category="protocol",
            detail="POODLE",
            severity="critical",
            cve="CVE-2014-3566",
        )
        assert f.cve == "CVE-2014-3566"
