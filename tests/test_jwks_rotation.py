"""JWT signer key rotation and bounded unknown-kid refresh tests."""
import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose import jwt

from gateway.auth import InvalidAccessToken, OIDCVerifier
from gateway.config import Settings


def make_keypair(kid):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    def b64(integer):
        value = integer.to_bytes((integer.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(value).decode().rstrip("=")
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = {"kid": kid, "kty": "RSA", "alg": "RS256",
              "n": b64(numbers.n), "e": b64(numbers.e)}
    return private, public


def create_signed(private, kid):
    return jwt.encode({
        "iss": "https://auth.example.com/realms/demo",
        "aud": "mcp-api", "sub": "example-user",
        "exp": int(time.time()) + 300,
        "typ": "Bearer", "scope": "mcp:read",
    }, private, algorithm="RS256", headers={"kid": kid})


def make_verifier():
    settings = Settings(
        "https://mcp.example.com/mcp",
        "https://auth.example.com/realms/demo",
        "mcp-api",
    )
    return OIDCVerifier(settings)


def test_jwks_rotation_after_cooldown(monkeypatch):
    first_private, first_public = make_keypair("first")
    second_private, second_public = make_keypair("second")
    jwks_data = [{"keys": [first_public]}]
    calls = []
    verifier = make_verifier()

    def fetch(url):
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": verifier.settings.issuer,
                    "jwks_uri": "https://auth.example.com/realms/demo/protocol/openid-connect/certs"}
        return jwks_data[0]

    monkeypatch.setattr("gateway.auth._fetch_json", fetch)
    assert verifier.verify(create_signed(first_private, "first"))["sub"] == "example-user"
    assert len(calls) == 2
    # Allow a rotation-specific refetch before the normal 300-second TTL.
    verifier._last_fetch_attempt -= 31
    jwks_data[0] = {"keys": [second_public]}
    assert verifier.verify(create_signed(second_private, "second"))["sub"] == "example-user"
    assert len(calls) == 4


def test_unknown_kid_does_not_trigger_unbounded_fetches(monkeypatch):
    first_private, first_public = make_keypair("first")
    unknown_private, _ = make_keypair("attacker")
    verifier = make_verifier()
    calls = []
    def fetch(url):
        calls.append(url)
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": verifier.settings.issuer,
                    "jwks_uri": "https://auth.example.com/certs"}
        return {"keys": [first_public]}

    monkeypatch.setattr("gateway.auth._fetch_json", fetch)
    assert verifier.verify(create_signed(first_private, "first"))["sub"] == "example-user"
    # Allow a single refresh after cooldown; repeated bad kids cannot force more.
    verifier._last_fetch_attempt -= 31
    for _ in range(10):
        with pytest.raises(InvalidAccessToken):
            verifier.verify(create_signed(unknown_private, "unknown-kid"))
    assert len(calls) == 4
