"""Generate demo-only self-signed TLS for a private Docker network.

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

DEST = Path("/dev-tls")
DEST.mkdir(parents=True, exist_ok=True)
CERT = DEST / "keycloak.pem"
KEY = DEST / "keycloak-key.pem"

if CERT.is_file() and KEY.is_file():
    print("Using existing demo TLS material.")
else:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "keycloak")
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("keycloak")]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(private, hashes.SHA256())
    )
    KEY.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(KEY, 0o600)
    os.chmod(CERT, 0o644)
    os.chown(KEY, 1000, 0)
    print("Generated ephemeral self-signed Keycloak certificate for local demo.")
