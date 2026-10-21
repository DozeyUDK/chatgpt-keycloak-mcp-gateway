"""Regression coverage for persisted demo TLS volume reuse and renewal."""
from __future__ import annotations

import datetime as dt
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from scripts.generate_dev_tls import RENEW_BEFORE, ensure_demo_tls


NOW = dt.datetime(2026, 10, 21, 12, 0, tzinfo=dt.timezone.utc)


def _pair(directory):
    return (directory / "keycloak.pem").read_bytes(), (directory / "keycloak-key.pem").read_bytes()


def _assert_cert_and_key(directory, when):
    pem, key_pem = _pair(directory)
    cert = x509.load_pem_x509_certificate(pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    assert cert.not_valid_before_utc <= when < cert.not_valid_after_utc
    assert "keycloak" in cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    assert stat.S_IMODE((directory / "keycloak-key.pem").stat().st_mode) == 0o600
    assert stat.S_IMODE((directory / "keycloak.pem").stat().st_mode) == 0o644
    assert not (directory / "keycloak.pem.next").exists()
    assert not (directory / "keycloak-key.pem.next").exists()


def test_reuses_valid_pair_without_changing_files(tmp_path):
    assert ensure_demo_tls(tmp_path, now=NOW) is True
    first = _pair(tmp_path)
    assert ensure_demo_tls(tmp_path, now=NOW + dt.timedelta(hours=2)) is False
    assert _pair(tmp_path) == first
    _assert_cert_and_key(tmp_path, NOW + dt.timedelta(hours=2))


@pytest.mark.parametrize("hours", [37, 73])
def test_renews_pair_approaching_expiry_or_already_expired(tmp_path, hours):
    assert ensure_demo_tls(tmp_path, now=NOW) is True
    first = _pair(tmp_path)
    later = NOW + dt.timedelta(hours=hours)
    assert ensure_demo_tls(tmp_path, now=later) is True
    assert _pair(tmp_path) != first
    _assert_cert_and_key(tmp_path, later)
    assert x509.load_pem_x509_certificate(_pair(tmp_path)[0]).not_valid_after_utc > later + RENEW_BEFORE


@pytest.mark.parametrize("damaged_file", ["keycloak.pem", "keycloak-key.pem"])
def test_corrupted_volume_material_is_recovered(tmp_path, damaged_file):
    ensure_demo_tls(tmp_path, now=NOW)
    (tmp_path / damaged_file).write_bytes(b"not a certificate or key")
    assert ensure_demo_tls(tmp_path, now=NOW + dt.timedelta(minutes=1)) is True
    _assert_cert_and_key(tmp_path, NOW + dt.timedelta(minutes=1))


def test_mismatched_key_is_not_reused(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    ensure_demo_tls(first, now=NOW)
    ensure_demo_tls(second, now=NOW)
    (first / "keycloak-key.pem").write_bytes((second / "keycloak-key.pem").read_bytes())
    assert ensure_demo_tls(first, now=NOW + dt.timedelta(minutes=2)) is True
    _assert_cert_and_key(first, NOW + dt.timedelta(minutes=2))
