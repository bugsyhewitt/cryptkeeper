# cryptkeeper — CLAUDE.md

Part of the necromancer suite (tool #21, TLS/SSL misconfiguration scanner).

## Stack

- Python 3.11+, uv for package management
- Click for CLI, pure stdlib `ssl` + `socket` — no external TLS library
- pytest for tests

## Architecture

```
src/cryptkeeper/
  payloads.py    — weakness pattern data: WEAK_CIPHERS, WEAK_PROTOCOLS, WeaknessFinding
  checker.py     — analysis logic: check_cipher_weakness, check_protocol_weakness, check_certificate, build_findings
  prober.py      — TLS connection: probe_tls (ssl + socket), _try_protocol for downgrade testing
  cli.py         — Click CLI: cryptkeeper scan --host --port --json --timeout
```

## Run / test

```bash
pip install -e ".[dev]"
pytest -q
cryptkeeper scan --host example.com
```

## v0.1 scope

- Cipher weakness detection (RC4, 3DES, NULL, EXPORT, ANON, MD5, CBC)
- Protocol version checking (SSLv3/TLS1.0/1.1 deprecated)
- Protocol downgrade probing (TLS 1.0 / 1.1 / SSLv3)
- Certificate validity, expiry, self-signed, SHA-1 signature
- JSON output mode
- 25+ tests (all prober tests mocked — no live network)

## Post-v0.1 directions

- STARTTLS support (SMTP, IMAP, FTP, LDAP)
- HSTS preload check integration with knell output
- Key exchange weakness (DHE < 2048 bits, ECDHE curve choices)
- Certificate Transparency log lookup
- Bulk scan mode (list of targets from file)
- Heartbleed probe (CVE-2014-0160)
