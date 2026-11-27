"""Cipher suite weakness patterns and protocol version definitions."""

from dataclasses import dataclass, field

WEAK_CIPHERS: list[str] = [
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT",
    "ANON",
    "MD5",
    "CBC",  # CBC ciphers vulnerable to BEAST in TLS 1.0
]

WEAK_PROTOCOLS: list[str] = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]

# CVE references for known attacks
PROTOCOL_CVES: dict[str, str] = {
    "SSLv2": "CVE-2016-0800",   # DROWN
    "SSLv3": "CVE-2014-3566",   # POODLE
    "TLSv1": "CVE-2011-3389",   # BEAST
    "TLSv1.1": None,
}

CIPHER_CVES: dict[str, str] = {
    "RC4": "CVE-2013-2566",
    "3DES": "CVE-2016-2183",    # SWEET32
    "EXPORT": "CVE-2015-0204",  # FREAK
}


@dataclass
class WeaknessFinding:
    target: str
    category: str   # "cipher" | "protocol" | "certificate" | "configuration"
    detail: str
    severity: str   # "critical" | "high" | "medium" | "low" | "info"
    cve: str | None = None
    extra: dict = field(default_factory=dict)
