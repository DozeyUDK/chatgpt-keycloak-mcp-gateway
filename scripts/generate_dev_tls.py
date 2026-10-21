"""Generate and refresh demo-only self-signed TLS for a private Docker network.

Not for production. Keycloak runs as UID 1000; MCP and smoke clients only
read the public certificate to trust this temporary local issuer.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


HOSTNAME = "keycloak"
RENEW_BEFORE = dt.timedelta(hours=12)


def _reusable(cert_path: Path, key_path: Path, now: dt.datetime) -> bool:
    """Reuse only a valid, matching keypair with enough lifetime remaining."""
    if not cert_path.is_file() or not key_path.is_file():
        return False
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not (cert.not_valid_before_utc <= now
                and cert.not_valid_after_utc > now + RENEW_BEFORE):
            return False
        names = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        if HOSTNAME not in names:
            return False
        if cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            return False
    except (ValueError, TypeError, OSError, x509.ExtensionNotFound):
        # Missing, malformed or mismatched TLS material must not be reused.
        return False
    return True


def ensure_demo_tls(
    dest: Path, *, now: dt.datetime | None = None, key_owner_uid: int | None = None
) -> bool:
    """Return True if a new pair was generated, False if reused.

    The caller must restart Keycloak after regeneration so that its HTTP
    listener and the MCP/JWKS clients agree on the renewed certificate.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    dest.mkdir(parents=True, exist_ok=True)
    cert_path = dest / "keycloak.pem"
    key_path = dest / "keycloak-key.pem"

    if _reusable(cert_path, key_path, now):
        print("Reusing valid demo TLS material.")
        return False

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOSTNAME)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(HOSTNAME)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private, hashes.SHA256())
    )

    # A crash between replaces may leave mismatched files; next run detects
    # that mismatch and recovers without requiring a manual volume deletion.
    temp_key = dest / "keycloak-key.pem.next"
    temp_cert = dest / "keycloak.pem.next"
    try:
        # Set restrictive permissions before writing any private-key bytes.
        key_fd = os.open(
            temp_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(key_fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        if key_owner_uid is not None:
            os.chown(temp_key, key_owner_uid, 0)
        temp_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(temp_cert, 0o644)
        os.replace(temp_key, key_path)
        os.replace(temp_cert, cert_path)
    finally:
        temp_key.unlink(missing_ok=True)
        temp_cert.unlink(missing_ok=True)
    print("Generated or renewed demo-only Keycloak TLS material.")
    return True


if __name__ == "__main__":
    ensure_demo_tls(Path("/dev-tls"), key_owner_uid=1000)
