"""Strict access-token validation using the issuer's OIDC discovery and JWKS.

The server is an OAuth resource server, NOT an authorization server. Never proxy
token requests or accept ID tokens as a substitute for an access token.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from jose import jwt
from jose.exceptions import JWTError

from .config import Settings


class AuthBackendError(Exception):
    """Issuer/JWKS temporarily unavailable or invalid."""


class InvalidAccessToken(Exception):
    """The caller's JWT is malformed, untrusted, or missing required claims."""


class InsufficientScope(Exception):
    """Valid token but missing the configured OAuth scope."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_json(url: str) -> dict:
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        response = opener.open(
            urllib.request.Request(url, headers={"Accept": "application/json"}),
            timeout=5.0,
        )
        with response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("Response is too large")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise ValueError("Expected object")
        return decoded
    except (ValueError, OSError, TimeoutError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuthBackendError("OIDC discovery or JWKS unavailable") from exc


def _same_https_origin(first: str, second: str) -> bool:
    left, right = urlsplit(first), urlsplit(second)
    return (
        right.scheme == "https"
        and (left.hostname, left.port) == (right.hostname, right.port)
        and right.username is None
        and right.password is None
        and not right.query
        and not right.fragment
    )


class OIDCVerifier:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._jwks: dict | None = None
        self._expires = 0.0

    def _get_jwks(self) -> dict:
        if self._jwks and time.monotonic() < self._expires:
            return self._jwks
        # Never accept untrusted URLs from a token. Discovery is constrained to
        # the configured issuer, with no redirects or cross-origin JWKS fetches.
        metadata = _fetch_json(f"{self.settings.issuer}/.well-known/openid-configuration")
        if metadata.get("issuer") != self.settings.issuer:
            raise AuthBackendError("OIDC issuer mismatch")
        jwks_uri = metadata.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not _same_https_origin(self.settings.issuer, jwks_uri):
            raise AuthBackendError("JWKS URI is not on the trusted issuer origin")
        jwks = _fetch_json(jwks_uri)
        if not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
            raise AuthBackendError("Invalid JWKS")
        self._jwks, self._expires = jwks, time.monotonic() + self.settings.jwks_cache_seconds
        return jwks

    def verify(self, token: str) -> dict:
        if not token or len(token) > 16384:
            raise InvalidAccessToken()
        try:
            claims = jwt.decode(
                token,
                self._get_jwks(),
                algorithms=["RS256"],
                issuer=self.settings.issuer,
                audience=self.settings.audience,
                options={
                    "verify_aud": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    "require_exp": True,
                },
            )
        except (JWTError, TypeError, ValueError, OverflowError) as exc:
            raise InvalidAccessToken() from exc
        if not isinstance(claims, dict) or claims.get("typ") != "Bearer":
            # Keycloak uses typ=Bearer in access tokens; refuse ID tokens.
            raise InvalidAccessToken()
        scope = claims.get("scope")
        # Keycloak client/realm roles NEVER grant OAuth scopes implicitly.
        if not isinstance(scope, str) or self.settings.required_scope not in scope.split():
            raise InsufficientScope()
        return claims
