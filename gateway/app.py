"""Minimal stateless Streamable HTTP MCP endpoint with OAuth resource metadata.

A demonstration resource server with one read-only tool, not a generic
reverse proxy or an arbitrary remote-command executor.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from .auth import AuthBackendError, InsufficientScope, InvalidAccessToken, OIDCVerifier
from .config import Settings
from .policy import Policy, load_policy
from .fs_safe import FileAccessDenied, read_text, write_text

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18")
MAX_REQUEST_BYTES = 65536
BEARER = re.compile(r"^Bearer ([A-Za-z0-9._~+/\-=]+)$", re.ASCII)
TOOLS = {
    "demo_ping": {
        "name": "demo_ping",
        "description": "Read-only demonstration tool. Returns a constant pong string.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    "permissions_inspect": {
        "name": "permissions_inspect",
        "description": "View agent capability status and administrative steps needed to enable locked features. Cannot edit policy.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    "fs_read": {
        "name": "fs_read",
        "description": "Read UTF-8 text from administrator-approved read-only roots.",
        "inputSchema": {
            "type": "object", "properties": {"path": {"type": "string"}},
            "required": ["path"], "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    },
    "fs_write": {
        "name": "fs_write",
        "description": "Atomically write UTF-8 text inside admin-approved writable roots. Never modifies policy.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"], "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
}


def _rpc_error(code: int, message: str, request_id: Any = None, status: int = 200) -> JSONResponse:
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        status_code=status,
    )


def create_app(settings: Settings | None = None, verifier: OIDCVerifier | None = None, policy: Policy | None = None) -> FastAPI:
    # Missing/invalid policy must prevent startup; no fallback to allow-all.
    settings = settings or Settings.from_env()
    verifier = verifier or OIDCVerifier(settings)
    policy = policy or load_policy(os.getenv("POLICY_FILE", "/etc/mcp/policy.json"))
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
            "scopes_supported": sorted(set([settings.required_scope] + (["mcp:write"] if policy.tools["fs_write"].enabled else []))),
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
            claims = verifier.verify(matched.group(1))
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
            result = {"tools": [TOOLS[name] for name in sorted(TOOLS) if policy.allowed(name, claims)]}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not policy.allowed(name, claims):
                return _rpc_error(-32602, "Unknown or unauthorized tool", request_id)
            if not isinstance(arguments, dict):
                return _rpc_error(-32602, "Invalid arguments", request_id)
            if name == "demo_ping":
                if arguments:
                    return _rpc_error(-32602, "Invalid arguments", request_id)
                output = "pong"
            elif name == "permissions_inspect":
                if arguments:
                    return _rpc_error(-32602, "Invalid arguments", request_id)
                output = json.dumps(policy.inspect(claims), sort_keys=True)
            elif name == "fs_read":
                if set(arguments) != {"path"} or not isinstance(arguments["path"], str):
                    return _rpc_error(-32602, "Invalid arguments", request_id)
                try:
                    output = read_text(policy.readable_roots, arguments["path"], policy.max_read_bytes)
                except (FileAccessDenied, OSError):
                    return _rpc_error(-32602, "File not allowed", request_id)
            elif name == "fs_write":
                if set(arguments) != {"path", "content"}:
                    return _rpc_error(-32602, "Invalid arguments", request_id)
                try:
                    count = write_text(policy.editable_roots, arguments["path"], arguments["content"], policy.max_write_bytes)
                except (FileAccessDenied, OSError):
                    return _rpc_error(-32602, "File not allowed", request_id)
                output = json.dumps({"bytes_written": count})
            else:
                return _rpc_error(-32602, "Unknown tool", request_id)
            result = {"content": [{"type": "text", "text": output}], "isError": False}
        else:
            return _rpc_error(-32601, "Method not found", request_id)
        return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})

    return app


# Uvicorn gateway.app:app, after environment variables have been supplied.
app = create_app()
