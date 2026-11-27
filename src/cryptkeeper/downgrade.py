"""Protocol downgrade testing — actively attempt weak TLS/SSL handshakes."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Optional


@dataclass
class DowngradeResult:
    protocol_requested: str
    negotiated_protocol: Optional[str]
    handshake_succeeded: bool
    cipher_negotiated: Optional[str]
    vulnerable: bool
    severity: str


PROTOCOL_TEST_ORDER = [
    "SSLv3",
    "TLSv1",
    "TLSv1.1",
    "TLSv1.2",
]

_SEVERITY_MAP = {
    "SSLv3": "critical",
    "TLSv1": "high",
    "TLSv1.1": "high",
    "TLSv1.2": "low",
}

_TLSVERSION_MAP = {
    "SSLv3": "SSLv3",
    "TLSv1": "TLSv1",
    "TLSv1.1": "TLSv1_1",
    "TLSv1.2": "TLSv1_2",
}


def _try_downgrade(
    host: str,
    port: int,
    protocol_name: str,
    timeout: int,
) -> tuple[bool, Optional[str], Optional[str]]:
    """Attempt a handshake restricted to `protocol_name`.

    Returns (succeeded, negotiated_protocol, cipher_name).
    """
    attr = _TLSVERSION_MAP.get(protocol_name)
    if attr is None:
        return False, None, None

    tls_version = getattr(ssl.TLSVersion, attr, None)
    if tls_version is None:
        return False, None, None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    except (AttributeError, ssl.SSLError):
        return False, None, None

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                negotiated = ssock.version()
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else None
                return True, negotiated, cipher_name
    except Exception:
        return False, None, None


def test_protocol_downgrade(
    host: str,
    port: int = 443,
    timeout: int = 5,
) -> list[DowngradeResult]:
    """Attempt handshakes with each protocol in PROTOCOL_TEST_ORDER.

    Returns list sorted by severity DESC (critical first).
    """
    sev_order = {"critical": 0, "high": 1, "low": 2}
    results: list[DowngradeResult] = []

    for proto in PROTOCOL_TEST_ORDER:
        severity = _SEVERITY_MAP.get(proto, "low")
        succeeded, negotiated, cipher = _try_downgrade(host, port, proto, timeout)
        results.append(
            DowngradeResult(
                protocol_requested=proto,
                negotiated_protocol=negotiated,
                handshake_succeeded=succeeded,
                cipher_negotiated=cipher,
                vulnerable=succeeded,
                severity=severity,
            )
        )

    results.sort(key=lambda r: sev_order.get(r.severity, 99))
    return results


def downgrade_summary(results: list[DowngradeResult]) -> str:
    """Return a brief human-readable summary of the downgrade test results."""
    vulnerable = [r for r in results if r.vulnerable]
    if not vulnerable:
        return "No protocol downgrade vulnerabilities detected."
    labels = ", ".join(r.protocol_requested for r in vulnerable)
    return f"Server accepts downgrade to: {labels}"
