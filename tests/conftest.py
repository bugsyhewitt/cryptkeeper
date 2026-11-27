"""Shared pytest fixtures for cryptkeeper tests."""

import datetime
import pytest


@pytest.fixture
def future_cert_info():
    """A clean, valid cert_info dict with a far-future expiry."""
    return {
        "subject_cn": "example.com",
        "cert_expiry": (
            datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=365)
        ).isoformat(),
        "cert_self_signed": False,
        "signature_algorithm": "sha256WithRSAEncryption",
    }


@pytest.fixture
def expired_cert_info():
    """A cert_info dict for an already-expired certificate."""
    return {
        "subject_cn": "example.com",
        "cert_expiry": (
            datetime.datetime.now(tz=datetime.timezone.utc)
            - datetime.timedelta(days=1)
        ).isoformat(),
        "cert_self_signed": False,
        "signature_algorithm": "sha256WithRSAEncryption",
    }
