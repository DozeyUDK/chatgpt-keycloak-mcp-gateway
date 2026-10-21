import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jose import jwt

from gateway.auth import AuthBackendError, InsufficientScope, InvalidAccessToken, OIDCVerifier
from gateway.config import Settings


@pytest.fixture
def fixture_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()

    def b64(value):
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    jwks = {"keys": [{"kty": "RSA", "use": "sig", "kid": "fixture-1", "alg": "RS256",
                       "n": b64(numbers.n), "e": b64(numbers.e)}]}
    return pem, jwks


@pytest.fixture
def verifier(monkeypatch, fixture_keys):
    settings = Settings("https://mcp.example.com/mcp", "https://auth.example.com/realms/demo", "mcp-api")
    verify = OIDCVerifier(settings)
    monkeypatch.setattr(verify, "_get_jwks", lambda: fixture_keys[1])
    return verify


def signed(pem, **changes):
    claims = {
        "iss": "https://auth.example.com/realms/demo",
        "aud": "mcp-api",
        "exp": int(time.time()) + 300,
        "typ": "Bearer",
        "sub": "example-user",
        "scope": "openid mcp:read",
    }
    claims.update(changes)
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "fixture-1"})


def test_valid_jwt(verifier, fixture_keys):
    assert verifier.verify(signed(fixture_keys[0]))["sub"] == "example-user"


@pytest.mark.parametrize("changes", [
    {"iss": "https://other.example.com/realms/demo"},
    {"aud": "different-api"},
    {"exp": int(time.time()) - 500},
    {"typ": "ID"},
])
def test_reject_wrong_claims(verifier, fixture_keys, changes):
    with pytest.raises(InvalidAccessToken):
        verifier.verify(signed(fixture_keys[0], **changes))


def test_exp_is_required(verifier, fixture_keys):
    claims = {"iss": verifier.settings.issuer, "aud": "mcp-api", "scope": "mcp:read", "typ": "Bearer"}
    encoded = jwt.encode(claims, fixture_keys[0], algorithm="RS256", headers={"kid": "fixture-1"})
    with pytest.raises(InvalidAccessToken):
        verifier.verify(encoded)


def test_keycloak_role_never_grants_oauth_scope(verifier, fixture_keys):
    encoded = signed(fixture_keys[0], scope="openid", realm_access={"roles": ["mcp:read"]},
                     resource_access={"mcp-api": {"roles": ["mcp:read"]}})
    with pytest.raises(InsufficientScope):
        verifier.verify(encoded)


def test_no_access_token(verifier):
    with pytest.raises(InvalidAccessToken):
        verifier.verify("")


def test_reject_unsigned_token(verifier):
    token = jwt.encode({"scope": "mcp:read", "exp": int(time.time()) + 300}, "unused", algorithm="HS256")
    with pytest.raises(InvalidAccessToken):
        verifier.verify(token)


def test_discovery_issuer_mismatch(monkeypatch):
    settings = Settings("https://mcp.example.com/mcp", "https://auth.example.com/realms/demo", "mcp-api")
    monkeypatch.setattr("gateway.auth._fetch_json", lambda url: {
        "issuer": "https://evil.example.com/realms/demo",
        "jwks_uri": "https://evil.example.com/jwks",
    })
    with pytest.raises(AuthBackendError):
        OIDCVerifier(settings)._get_jwks()


def test_discovery_rejects_cross_origin_jwks(monkeypatch):
    settings = Settings("https://mcp.example.com/mcp", "https://auth.example.com/realms/demo", "mcp-api")
    monkeypatch.setattr("gateway.auth._fetch_json", lambda url: {
        "issuer": settings.issuer,
        "jwks_uri": "https://attacker.example.com/keys",
    })
    with pytest.raises(AuthBackendError):
        OIDCVerifier(settings)._get_jwks()


@pytest.mark.parametrize("bad_url", ["http://mcp.example.com/mcp", "https://mcp.example.com/wrong",
                                       "https://mcp.example.com/mcp?token=x", "https://a@b.example.com/mcp"])
def test_config_rejects_unsafe_public_url(bad_url):
    with pytest.raises(ValueError):
        Settings(bad_url, "https://auth.example.com/realms/demo", "mcp-api")
