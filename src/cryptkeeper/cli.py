"""CLI entry point for cryptkeeper."""

from __future__ import annotations

import json
import sys

import click

from . import __version__
from .checker import build_findings
from .prober import probe_tls


@click.group()
@click.version_option(__version__)
def main() -> None:
    """cryptkeeper — TLS/SSL misconfiguration scanner."""


@main.command()
@click.option("--host", required=True, help="Target hostname")
@click.option("--port", default=443, show_default=True, type=int, help="Target port")
@click.option("--json", "output_json", is_flag=True, help="Output JSON")
@click.option(
    "--timeout",
    default=10,
    show_default=True,
    type=int,
    help="Connection timeout in seconds",
)
def scan(host: str, port: int, output_json: bool, timeout: int) -> None:
    """Scan a host for TLS/SSL misconfigurations."""
    try:
        result = probe_tls(host, port, timeout)
    except Exception as exc:
        msg = {"error": str(exc), "host": host, "port": port}
        if output_json:
            click.echo(json.dumps(msg, indent=2))
        else:
            click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    findings = build_findings(f"{host}:{port}", result)

    if output_json:
        output = {
            "host": host,
            "port": port,
            "protocol": result["protocol"],
            "cipher": result["cipher_name"],
            "cipher_bits": result["cipher_bits"],
            "cert_expiry": result["cert_expiry"],
            "cert_self_signed": result["cert_self_signed"],
            "supports_tls10": result["supports_tls10"],
            "supports_tls11": result["supports_tls11"],
            "supports_sslv3": result["supports_sslv3"],
            "findings": [
                {
                    "category": f.category,
                    "detail": f.detail,
                    "severity": f.severity,
                    "cve": f.cve,
                }
                for f in findings
            ],
        }
        click.echo(json.dumps(output, indent=2))
        return

    # Human-readable output
    click.echo(f"\ncryptkeeper scan: {host}:{port}")
    click.echo(f"  Protocol  : {result['protocol']}")
    click.echo(f"  Cipher    : {result['cipher_name']} ({result['cipher_bits']} bits)")
    click.echo(f"  Cert CN   : {result.get('subject_cn', 'unknown')}")
    click.echo(f"  Cert Expiry: {result['cert_expiry']}")
    click.echo(f"  Self-signed: {result['cert_self_signed']}")
    click.echo(f"  Sig alg   : {result.get('signature_algorithm', 'unknown')}")
    click.echo(f"  TLS 1.0   : {'YES (!)' if result['supports_tls10'] else 'no'}")
    click.echo(f"  TLS 1.1   : {'YES (!)' if result['supports_tls11'] else 'no'}")
    click.echo(f"  SSLv3     : {'YES (!)' if result['supports_sslv3'] else 'no'}")
    click.echo()

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(f.severity, 99))

    if not findings_sorted:
        click.echo("  No weaknesses found.")
    else:
        click.echo(f"  Findings ({len(findings_sorted)}):")
        for f in findings_sorted:
            cve_tag = f" [{f.cve}]" if f.cve else ""
            click.echo(f"  [{f.severity.upper():8}] {f.category}: {f.detail}{cve_tag}")
    click.echo()
