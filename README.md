# cryptkeeper

TLS/SSL misconfiguration scanner for bug bounty and pentesting.

cryptkeeper probes a target host's TLS handshake and reports weak cipher suites, deprecated protocol versions, certificate issues, and configurations that enable BEAST/POODLE-class attacks.

## Install

```bash
pip install cryptkeeper
# or from source:
pip install -e .
```

## Usage

```bash
cryptkeeper scan --host example.com
cryptkeeper scan --host example.com --port 8443
cryptkeeper scan --host example.com --json
cryptkeeper scan --host example.com --timeout 5
```

### Example output

```
cryptkeeper scan: example.com:443
  Protocol  : TLSv1.3
  Cipher    : TLS_AES_256_GCM_SHA384 (256 bits)
  Cert CN   : example.com
  Cert Expiry: 2025-12-01T00:00:00+00:00
  Self-signed: False
  Sig alg   : sha256WithRSAEncryption
  TLS 1.0   : no
  TLS 1.1   : no
  SSLv3     : no

  No weaknesses found.
```

## What it checks

| Category | Details |
|---|---|
| Cipher weakness | RC4 (critical), NULL/EXPORT/ANON (critical), 3DES/DES/MD5 (high), CBC (medium) |
| Protocol version | SSLv3 (critical/POODLE), TLS 1.0 (high/BEAST), TLS 1.1 (medium) |
| Protocol downgrade | Tests whether server accepts connections at deprecated protocol versions |
| Certificate expiry | Expired (critical), expiring within 30 days (low) |
| Self-signed | Medium severity |
| SHA-1 signature | High severity (deprecated) |

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Part of the necromancer suite

cryptkeeper fills the TLS analysis gap in the necromancer offensive-security suite. `knell` checks for HSTS/security headers; cryptkeeper probes the TLS handshake itself.
