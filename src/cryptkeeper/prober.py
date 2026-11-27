"""TLS connection prober — connects to target, negotiates TLS, extracts info."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import Optional


def _try_protocol(host: str, port: int, protocol: int, timeout: int) -> bool:
    """Return True if the server accepts a connection at the given ssl protocol version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Restrict to the specific max version if the platform supports it
        try:
            if protocol == ssl.TLSVersion.SSLv3:  # type: ignore[attr-defined]
                ctx.maximum_version = ssl.TLSVersion.SSLv3  # type: ignore[attr-defined]
                ctx.minimum_version = ssl.TLSVersion.SSLv3  # type: ignore[attr-defined]
            elif protocol == ssl.TLSVersion.TLSv1:
                ctx.maximum_version = ssl.TLSVersion.TLSv1
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            elif protocol == ssl.TLSVersion.TLSv1_1:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        except AttributeError:
            return False
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _cert_is_self_signed(cert: dict) -> bool:
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    # Both subject and issuer are tuples of ((k, v), ...) pairs
    return subject == issuer


def _cert_expiry(cert: dict) -> Optional[str]:
    not_after = cert.get("notAfter")
    if not_after:
        try:
            dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
        except ValueError:
            return not_after
    return None


def _extract_cn(rdn_seq: tuple) -> str:
    for rdn in rdn_seq:
        for key, val in rdn:
            if key == "commonName":
                return val
    return ""


def probe_tls(host: str, port: int = 443, timeout: int = 10) -> dict:
    """Connect to host:port, negotiate TLS, and return diagnostic info.

    Returns a dict with keys: protocol, cipher_name, cipher_bits, cert_subject,
    cert_issuer, cert_expiry, cert_self_signed, subject_cn, signature_algorithm,
    supports_tls10, supports_tls11, supports_sslv3.

    Raises ConnectionRefusedError, socket.gaierror, or ssl.SSLError on failure.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            protocol = ssock.version() or ""
            cipher_name, _proto, cipher_bits = ssock.cipher() or ("", "", 0)
            der_cert = ssock.getpeercert(binary_form=True)
            cert = ssock.getpeercert() or {}

    # Parse cert details
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    self_signed = _cert_is_self_signed(cert)
    expiry = _cert_expiry(cert)
    subject_cn = _extract_cn(subject)

    # Signature algorithm is not exposed by Python's ssl module from getpeercert();
    # we detect SHA-1 via the DER bytes heuristic if available, else mark unknown.
    sig_alg = _guess_sig_algorithm(der_cert) if der_cert else ""

    # Protocol downgrade probes
    supports_tls10 = _try_protocol(host, port, ssl.TLSVersion.TLSv1, timeout)  # type: ignore[attr-defined]
    supports_tls11 = _try_protocol(host, port, ssl.TLSVersion.TLSv1_1, timeout)  # type: ignore[attr-defined]
    supports_sslv3 = False  # SSLv3 disabled in modern OpenSSL; probe skipped

    return {
        "protocol": protocol,
        "cipher_name": cipher_name,
        "cipher_bits": cipher_bits,
        "cert_subject": dict(_flatten_rdn(subject)),
        "cert_issuer": dict(_flatten_rdn(issuer)),
        "cert_expiry": expiry,
        "cert_self_signed": self_signed,
        "subject_cn": subject_cn,
        "signature_algorithm": sig_alg,
        "supports_tls10": supports_tls10,
        "supports_tls11": supports_tls11,
        "supports_sslv3": supports_sslv3,
    }


def _flatten_rdn(rdn_seq: tuple) -> list[tuple[str, str]]:
    result = []
    for rdn in rdn_seq:
        for k, v in rdn:
            result.append((k, v))
    return result


def _guess_sig_algorithm(der_bytes: bytes) -> str:
    """Heuristic: search the DER bytes for known OID byte sequences.

    sha1WithRSAEncryption OID = 1.2.840.113549.1.1.5
    sha256WithRSAEncryption OID = 1.2.840.113549.1.1.11
    """
    # sha1WithRSAEncryption DER OID bytes
    sha1_oid = bytes([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05])
    if sha1_oid in der_bytes:
        return "sha1WithRSAEncryption"
    return "sha256WithRSAEncryption"
