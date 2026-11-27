"""Tests for prober.py — TLS connection prober (all mocked)."""

from __future__ import annotations

import datetime
import socket
import ssl
from unittest.mock import MagicMock, patch, call

import pytest


def _make_mock_ssock(
    version="TLSv1.3",
    cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
    cert=None,
    der_cert=b"\x30\x82",
):
    ssock = MagicMock()
    ssock.version.return_value = version
    ssock.cipher.return_value = cipher
    ssock.getpeercert.side_effect = lambda binary_form=False: der_cert if binary_form else (cert or {})
    return ssock


def _wrap_in_ctx_manager(mock_obj):
    """Make mock_obj usable as both context manager and regular object."""
    mock_obj.__enter__ = MagicMock(return_value=mock_obj)
    mock_obj.__exit__ = MagicMock(return_value=False)
    return mock_obj


class TestProbeTls:
    def _probe_with_mock(self, ssock_mock=None, **probe_kwargs):
        from cryptkeeper.prober import probe_tls

        if ssock_mock is None:
            ssock_mock = _make_mock_ssock()
        _wrap_in_ctx_manager(ssock_mock)

        sock_mock = MagicMock()
        _wrap_in_ctx_manager(sock_mock)

        ctx_mock = MagicMock()
        ctx_mock.wrap_socket.return_value = ssock_mock

        with patch("socket.create_connection", return_value=sock_mock), \
             patch("ssl.create_default_context", return_value=ctx_mock), \
             patch("cryptkeeper.prober._try_protocol", return_value=False):
            result = probe_tls("example.com", **probe_kwargs)
        return result

    def test_returns_dict_with_protocol_key(self):
        result = self._probe_with_mock()
        assert "protocol" in result

    def test_returns_cipher_name(self):
        ssock = _make_mock_ssock(cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256))
        result = self._probe_with_mock(ssock_mock=ssock)
        assert result["cipher_name"] == "ECDHE-RSA-AES256-GCM-SHA384"

    def test_returns_cipher_bits(self):
        ssock = _make_mock_ssock(cipher=("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256))
        result = self._probe_with_mock(ssock_mock=ssock)
        assert result["cipher_bits"] == 256

    def test_returns_cert_self_signed_boolean(self):
        result = self._probe_with_mock()
        assert isinstance(result["cert_self_signed"], bool)

    def test_returns_cert_expiry_string_or_none(self):
        result = self._probe_with_mock()
        assert result["cert_expiry"] is None or isinstance(result["cert_expiry"], str)

    def test_connection_refused_raises(self):
        from cryptkeeper.prober import probe_tls

        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            with pytest.raises(ConnectionRefusedError):
                probe_tls("127.0.0.1", port=9)

    def test_unknown_host_raises(self):
        from cryptkeeper.prober import probe_tls

        with patch("socket.create_connection", side_effect=socket.gaierror("unknown host")):
            with pytest.raises(socket.gaierror):
                probe_tls("nonexistent.invalid")

    def test_cert_not_after_parsed(self):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Let's Encrypt"),),),
            "notAfter": "Dec  1 00:00:00 2099 GMT",
        }
        ssock = _make_mock_ssock(cert=cert)
        result = self._probe_with_mock(ssock_mock=ssock)
        assert result["cert_expiry"] is not None
        assert "2099" in result["cert_expiry"]

    def test_self_signed_detected_when_subject_equals_issuer(self):
        rdn = ((("commonName", "example.com"),),)
        cert = {
            "subject": rdn,
            "issuer": rdn,
            "notAfter": "Dec  1 00:00:00 2099 GMT",
        }
        ssock = _make_mock_ssock(cert=cert)
        result = self._probe_with_mock(ssock_mock=ssock)
        assert result["cert_self_signed"] is True

    def test_not_self_signed_when_subject_differs_from_issuer(self):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Let's Encrypt Authority X3"),),),
            "notAfter": "Dec  1 00:00:00 2099 GMT",
        }
        ssock = _make_mock_ssock(cert=cert)
        result = self._probe_with_mock(ssock_mock=ssock)
        assert result["cert_self_signed"] is False
