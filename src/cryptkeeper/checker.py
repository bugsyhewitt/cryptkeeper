"""TLS/SSL weakness analysis — cipher, protocol, and certificate checks."""

from __future__ import annotations

import datetime
from typing import Optional

from .payloads import (
    CIPHER_CVES,
    PROTOCOL_CVES,
    WEAK_CIPHERS,
    WEAK_PROTOCOLS,
    WeaknessFinding,
)


def check_cipher_weakness(cipher_name: str) -> Optional[str]:
    """Return severity if cipher is weak, None if fine."""
    upper = cipher_name.upper()
    for weak in WEAK_CIPHERS:
        if weak in upper:
            if weak in ("RC4", "NULL", "EXPORT", "ANON"):
                return "critical"
            if weak in ("DES", "3DES", "MD5"):
                return "high"
            if weak == "CBC":
                return "medium"
    return None


def check_protocol_weakness(protocol_version: str) -> Optional[str]:
    """Return severity if protocol is weak/deprecated, None if fine."""
    normalized = protocol_version.replace(" ", "").replace("_", "")
    # Normalize common representations
    mapping = {
        "SSLV2": "SSLv2",
        "SSLV3": "SSLv3",
        "TLSV1": "TLSv1",
        "TLSV1.0": "TLSv1",
        "TLSV1.1": "TLSv1.1",
        "TLSV1.2": None,
        "TLSV1.3": None,
    }
    key = normalized.upper().replace("TLS_", "TLS").replace("SSL_", "SSL")
    if key in mapping:
        canonical = mapping[key]
        if canonical is None:
            return None
    else:
        canonical = protocol_version

    if canonical in ("SSLv2",):
        return "critical"
    if canonical in ("SSLv3", "TLSv1"):
        return "critical" if canonical == "SSLv3" else "high"
    if canonical in ("TLSv1.1",):
        return "medium"
    return None


def check_certificate(cert_info: dict) -> list[WeaknessFinding]:
    """Check certificate for issues and return a list of findings."""
    findings: list[WeaknessFinding] = []
    target = cert_info.get("subject_cn", cert_info.get("subject", "unknown"))

    # Expired or expiring
    expiry_str = cert_info.get("cert_expiry") or cert_info.get("not_after")
    if expiry_str:
        try:
            expiry = datetime.datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            delta = expiry - now
            if delta.total_seconds() < 0:
                findings.append(
                    WeaknessFinding(
                        target=target,
                        category="certificate",
                        detail="Certificate is expired",
                        severity="critical",
                    )
                )
            elif delta.days <= 30:
                findings.append(
                    WeaknessFinding(
                        target=target,
                        category="certificate",
                        detail=f"Certificate expires in {delta.days} days",
                        severity="low",
                    )
                )
        except (ValueError, TypeError):
            pass

    # Self-signed
    if cert_info.get("cert_self_signed"):
        findings.append(
            WeaknessFinding(
                target=target,
                category="certificate",
                detail="Certificate is self-signed",
                severity="medium",
            )
        )

    # SHA-1 signature
    sig_alg = cert_info.get("signature_algorithm", "")
    if "sha1" in sig_alg.lower() or "sha-1" in sig_alg.lower():
        findings.append(
            WeaknessFinding(
                target=target,
                category="certificate",
                detail=f"Weak signature algorithm: {sig_alg}",
                severity="high",
            )
        )

    # Wildcard cert — informational only
    cn = cert_info.get("subject_cn", "")
    if cn.startswith("*."):
        findings.append(
            WeaknessFinding(
                target=target,
                category="certificate",
                detail=f"Wildcard certificate ({cn})",
                severity="info",
            )
        )

    return findings


def build_findings(target: str, probe_result: dict) -> list[WeaknessFinding]:
    """Convert a probe_tls result into a list of WeaknessFinding objects."""
    findings: list[WeaknessFinding] = []

    # Cipher check
    cipher_name = probe_result.get("cipher_name", "")
    sev = check_cipher_weakness(cipher_name)
    if sev:
        cve = None
        for token, c in CIPHER_CVES.items():
            if token in cipher_name.upper():
                cve = c
                break
        findings.append(
            WeaknessFinding(
                target=target,
                category="cipher",
                detail=f"Weak cipher in use: {cipher_name}",
                severity=sev,
                cve=cve,
            )
        )

    # Protocol check
    protocol = probe_result.get("protocol", "")
    sev = check_protocol_weakness(protocol)
    if sev:
        cve = PROTOCOL_CVES.get(protocol)
        findings.append(
            WeaknessFinding(
                target=target,
                category="protocol",
                detail=f"Deprecated protocol in use: {protocol}",
                severity=sev,
                cve=cve,
            )
        )

    # Downgrade protocol checks
    for proto_key, proto_label in [
        ("supports_sslv3", "SSLv3"),
        ("supports_tls10", "TLSv1"),
        ("supports_tls11", "TLSv1.1"),
    ]:
        if probe_result.get(proto_key):
            sev = check_protocol_weakness(proto_label)
            if sev:
                findings.append(
                    WeaknessFinding(
                        target=target,
                        category="protocol",
                        detail=f"Server accepts downgrade to {proto_label}",
                        severity=sev,
                        cve=PROTOCOL_CVES.get(proto_label),
                    )
                )

    # Certificate checks
    findings.extend(check_certificate(probe_result))

    return findings
