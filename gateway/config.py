"""Fail-closed configuration for a public OAuth-protected MCP resource."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import urlsplit


def _https_url(raw: str, name: str, *, path: str | None = None) -> str:
    value = raw.strip().rstrip("/")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (path is not None and parsed.path != path)
    ):
        raise ValueError(f"{name} must be an HTTPS URL with the expected path, without query, fragment or userinfo")
    return value


@dataclass(frozen=True)
class Settings:
    public_url: str
    issuer: str
    audience: str
    required_scope: str = "mcp:read"
    jwks_cache_seconds: int = 300
    allowed_origins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "public_url", _https_url(self.public_url, "MCP_PUBLIC_URL", path="/mcp"))
        object.__setattr__(self, "issuer", _https_url(self.issuer, "KEYCLOAK_ISSUER"))
        if not self.audience.strip() or self.audience != self.audience.strip():
            raise ValueError("KEYCLOAK_AUDIENCE is required")
        if not self.required_scope.strip() or len(self.required_scope.split()) != 1:
            raise ValueError("MCP_REQUIRED_SCOPE must be one OAuth scope token")
        if self.jwks_cache_seconds < 30 or self.jwks_cache_seconds > 3600:
            raise ValueError("JWKS_CACHE_SECONDS must be between 30 and 3600")
        if not isinstance(self.allowed_origins, (tuple, list)):
            raise ValueError("MCP_ALLOWED_ORIGINS must be an array of origins")
        for origin in self.allowed_origins:
            if not isinstance(origin, str) or _https_url(origin, "MCP_ALLOWED_ORIGINS", path="") != origin:
                raise ValueError("MCP_ALLOWED_ORIGINS entries must be exact HTTPS origins")


    @property
    def origin(self) -> str:
        parts = urlsplit(self.public_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def metadata_url(self) -> str:
        return f"{self.origin}/.well-known/oauth-protected-resource"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            public_url=os.environ["MCP_PUBLIC_URL"],
            issuer=os.environ["KEYCLOAK_ISSUER"],
            audience=os.environ["KEYCLOAK_AUDIENCE"],
            required_scope=os.getenv("MCP_REQUIRED_SCOPE", "mcp:read"),
            jwks_cache_seconds=int(os.getenv("JWKS_CACHE_SECONDS", "300")),
            allowed_origins=tuple(json.loads(os.getenv("MCP_ALLOWED_ORIGINS", "[]"))),
        )
