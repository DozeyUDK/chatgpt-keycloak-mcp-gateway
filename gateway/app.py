"""Minimal stateless Streamable HTTP MCP endpoint with OAuth resource metadata.

A demonstration resource server with one read-only tool, not a generic
reverse proxy or an arbitrary remote-command executor.
"""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .auth import AuthBackendError, InsufficientScope, InvalidAccessToken, OIDCVerifier
from .config import Settings

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18")
MAX_REQUEST_BYTES = 65536
BEARER = re.compile(r"^Bearer ([A-Za-z0-9._~+/\-=]+)$", re.ASCII)
TOOL = {
    "name": "demo_ping",
    "description": "Read-only demonstration tool. Returns a constant pong string.",
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
}


def _rpc_error(code: int, message: str, request_id: Any = None, status: int = 200) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        status_code=status,
    )


def create_app(settings: Settings | None = None, verifier: OIDCVerifier | None = None) -> FastAPI:
    # Settings are loaded explicitly so missing values fail before exposure.
    settings = settings or Settings.from_env()
    verifier = verifier or OIDCVerifier(settings)
    app = FastAPI(title="Example ChatGPT Keycloak MCP Gateway", docs_url=None, redoc_url=None, openapi_url=None)

    def _challenge(*, code: str | None = None, status: int = 401) -> JSONResponse:
        value = f'Bearer resource_metadata="{settings.metadata_url}", scope="{settings.required_scope}"'
        if code:
            value += f', error="{code}"'
        return JSONResponse(
            {"error": "unauthorized" if status == 401 else "forbidden"},
            status_code=status,
            headers={"WWW-Authenticate": value, "Cache-Control": "no-store"},
        )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/.well-known/oauth-protected-resource")
    @app.get("/.well-known/oauth-protected-resource/mcp")
    def protected_resource_metadata() -> dict:
        return {
            "resource": settings.public_url,
            "authorization_servers": [settings.issuer],
            "scopes_supported": [settings.required_scope],
            "bearer_methods_supported": ["header"],
        }

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        # Authenticate before reading/parsing requests or exposing tool details.
        auth_header = request.headers.get("authorization", "")
        matched = BEARER.fullmatch(auth_header)
        if not matched:
            return _challenge()
        try:
            verifier.verify(matched.group(1))
        except InvalidAccessToken:
            return _challenge(code="invalid_token")
        except InsufficientScope:
            return _challenge(code="insufficient_scope", status=403)
        except AuthBackendError:
            return JSONResponse({"error": "authentication_service_unavailable"}, status_code=503)

        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return _rpc_error(-32600, "application/json required", status=415)
        try:
            content_length = int(request.headers.get("content-length") or 0)
        except ValueError:
            return _rpc_error(-32600, "invalid content length", status=400)
        if content_length > MAX_REQUEST_BYTES or content_length < 0:
            return _rpc_error(-32600, "request too large", status=413)
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > MAX_REQUEST_BYTES:
                return _rpc_error(-32600, "request too large", status=413)
        raw = bytes(data)
        try:
            msg = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return _rpc_error(-32700, "Parse error", status=400)
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return _rpc_error(-32600, "Invalid Request", status=400)
        method = msg.get("method")
        request_id = msg.get("id")
        if not isinstance(method, str):
            return _rpc_error(-32600, "Invalid Request", request_id, status=400)
        # MCP notifications have no JSON-RPC id and must not receive a body.
        if method.startswith("notifications/") and "id" not in msg:
            return Response(status_code=202)
        if "id" not in msg or not isinstance(request_id, (str, int)):
            return _rpc_error(-32600, "Invalid Request", status=400)
        params = msg.get("params") or {}
        if not isinstance(params, dict):
            return _rpc_error(-32602, "Invalid params", request_id)
        if method == "initialize":
            version = params.get("protocolVersion")
            if version not in SUPPORTED_VERSIONS:
                version = SUPPORTED_VERSIONS[0]
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "keycloak-mcp-example", "version": "0.1.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [TOOL]}
        elif method == "tools/call":
            if params.get("name") != TOOL["name"] or params.get("arguments", {}) != {}:
                return _rpc_error(-32602, "Unknown tool or invalid arguments", request_id)
            result = {"content": [{"type": "text", "text": "pong"}], "isError": False}
        else:
            return _rpc_error(-32601, "Method not found", request_id)
        return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})

    return app


# Uvicorn gateway.app:app, after environment variables have been supplied.
app = create_app()
