"""Tests for downgrade.py — protocol downgrade testing (all mocked)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cryptkeeper.downgrade import DowngradeResult
from cryptkeeper.downgrade import downgrade_summary
from cryptkeeper.downgrade import test_protocol_downgrade as run_downgrade


def _mock_no_downgrade(host, port, proto, timeout):
    return False, None, None


def _mock_all_vulnerable(host, port, proto, timeout):
    return True, proto, "RC4-SHA"


class TestTestProtocolDowngrade:
    def test_returns_list(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        assert isinstance(results, list)

    def test_each_result_has_non_none_protocol_requested(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        for r in results:
            assert r.protocol_requested is not None

    def test_vulnerable_true_when_handshake_succeeded(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_all_vulnerable):
            results = run_downgrade("example.com")
        for r in results:
            assert r.vulnerable is True
            assert r.handshake_succeeded is True

    def test_vulnerable_false_when_handshake_failed(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        for r in results:
            assert r.vulnerable is False
            assert r.handshake_succeeded is False

    def test_severity_critical_for_sslv3(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        sslv3_results = [r for r in results if r.protocol_requested == "SSLv3"]
        assert len(sslv3_results) == 1
        assert sslv3_results[0].severity == "critical"

    def test_severity_high_for_tls10(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        tls10_results = [r for r in results if r.protocol_requested == "TLSv1"]
        assert len(tls10_results) == 1
        assert tls10_results[0].severity == "high"

    def test_severity_high_for_tls11(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        tls11_results = [r for r in results if r.protocol_requested == "TLSv1.1"]
        assert len(tls11_results) == 1
        assert tls11_results[0].severity == "high"

    def test_results_sorted_critical_first(self):
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        sev_order = {"critical": 0, "high": 1, "low": 2}
        for i in range(len(results) - 1):
            assert sev_order.get(results[i].severity, 99) <= sev_order.get(results[i + 1].severity, 99)

    def test_covers_all_protocols_in_order(self):
        from cryptkeeper.downgrade import PROTOCOL_TEST_ORDER
        with patch("cryptkeeper.downgrade._try_downgrade", side_effect=_mock_no_downgrade):
            results = run_downgrade("example.com")
        requested = {r.protocol_requested for r in results}
        assert set(PROTOCOL_TEST_ORDER) == requested


class TestDowngradeSummary:
    def test_returns_non_empty_string(self):
        results = [
            DowngradeResult(
                protocol_requested="TLSv1",
                negotiated_protocol=None,
                handshake_succeeded=False,
                cipher_negotiated=None,
                vulnerable=False,
                severity="high",
            )
        ]
        summary = downgrade_summary(results)
        assert isinstance(summary, str)
        assert len(summary) > 0

    def test_no_vulnerabilities_safe_message(self):
        results = [
            DowngradeResult(
                protocol_requested="SSLv3",
                negotiated_protocol=None,
                handshake_succeeded=False,
                cipher_negotiated=None,
                vulnerable=False,
                severity="critical",
            )
        ]
        summary = downgrade_summary(results)
        assert "no" in summary.lower() or "not" in summary.lower() or "detected" in summary.lower()

    def test_vulnerability_names_protocol(self):
        results = [
            DowngradeResult(
                protocol_requested="TLSv1",
                negotiated_protocol="TLSv1",
                handshake_succeeded=True,
                cipher_negotiated="RC4-SHA",
                vulnerable=True,
                severity="high",
            )
        ]
        summary = downgrade_summary(results)
        assert "TLSv1" in summary


class TestCLIDowngradeCommand:
    def test_downgrade_command_accepted_by_runner(self):
        from cryptkeeper.cli import main

        runner = CliRunner()
        with patch(
            "cryptkeeper.cli.test_protocol_downgrade",
            return_value=[
                DowngradeResult(
                    protocol_requested="SSLv3",
                    negotiated_protocol=None,
                    handshake_succeeded=False,
                    cipher_negotiated=None,
                    vulnerable=False,
                    severity="critical",
                )
            ],
        ):
            result = runner.invoke(main, ["downgrade", "--host", "example.com"])
        assert result.exit_code == 0

    def test_downgrade_command_json_output(self):
        from cryptkeeper.cli import main

        runner = CliRunner()
        with patch(
            "cryptkeeper.cli.test_protocol_downgrade",
            return_value=[
                DowngradeResult(
                    protocol_requested="TLSv1",
                    negotiated_protocol="TLSv1",
                    handshake_succeeded=True,
                    cipher_negotiated="RC4-SHA",
                    vulnerable=True,
                    severity="high",
                )
            ],
        ):
            result = runner.invoke(main, ["downgrade", "--host", "example.com", "--json"])
        assert result.exit_code == 0
        data = __import__("json").loads(result.output)
        assert "results" in data
        assert data["results"][0]["vulnerable"] is True

    def test_scan_downgrade_flag_accepted(self):
        import datetime
        from cryptkeeper.cli import main

        runner = CliRunner()
        probe_result = {
            "protocol": "TLSv1.3",
            "cipher_name": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "cert_expiry": (
                __import__("datetime").datetime.now(tz=__import__("datetime").timezone.utc)
                + __import__("datetime").timedelta(days=365)
            ).isoformat(),
            "cert_self_signed": False,
            "signature_algorithm": "sha256WithRSAEncryption",
            "subject_cn": "example.com",
            "supports_tls10": False,
            "supports_tls11": False,
            "supports_sslv3": False,
        }
        with patch("cryptkeeper.cli.probe_tls", return_value=probe_result), patch(
            "cryptkeeper.cli.test_protocol_downgrade",
            return_value=[
                DowngradeResult(
                    protocol_requested="SSLv3",
                    negotiated_protocol=None,
                    handshake_succeeded=False,
                    cipher_negotiated=None,
                    vulnerable=False,
                    severity="critical",
                )
            ],
        ):
            result = runner.invoke(main, ["scan", "--host", "example.com", "--downgrade"])
        assert result.exit_code == 0
        assert "Downgrade" in result.output or "downgrade" in result.output.lower()
