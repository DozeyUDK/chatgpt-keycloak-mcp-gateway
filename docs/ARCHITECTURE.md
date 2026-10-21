# Architecture

External OAuth-enabled MCP client
    |
    | HTTPS, authorization code + PKCE S256 with Keycloak
    v
Trusted HTTPS reverse proxy / Cloudflare Tunnel
    |
    | private HTTP hop (loopback / private network only)
    v
FastAPI MCP resource server
    |-- /.well-known/oauth-protected-resource
    |-- /mcp, bearer JWT validation per request
    |-- demo_ping and permissions_inspect (default)
    |-- fs_read / fs_write (optional, policy + RBAC + host mounts)
    |-- structured authorization audit (no raw file content)
    |
    +-- HTTPS OIDC discovery and JWKS -> Keycloak realm

The code never exposes the Keycloak administrative API or a generic shell.
File writes are possible only when an administrator enables them in a private,
read-only mounted policy and separately mounts an approved writable directory.
All tool calls require matching OAuth scopes plus configured roles/groups.
Authorization decisions are logged without raw arguments. These boundaries do
not prevent model-level prompt injection or confused-deputy behavior; see
[Threat Model](THREAT_MODEL.md).

Note: OAuth client registration and token issuance happen entirely at the
authorization server. Resource-server metadata is NOT authorization-server
metadata. This project does not impersonate Keycloak.

## Protocol scope

The demonstration uses a narrow, handwritten JSON-RPC 2.0 subset for simple
MCP requests over HTTP POST. This keeps the small example transparent, but
introduces protocol-drift risk compared with the official MCP Python SDK. It is stateless and does not support server-side event streaming,
resumability, subscriptions, or session IDs. It is not a drop-in substitute
for a complete MCP SDK transport implementation.

The HTTP transport validates the optional Origin and MCP-Protocol-Version
headers. Browser client origins must be explicitly approved in
MCP_ALLOWED_ORIGINS. Clients that omit Origin use bearer authentication.
Authenticated GET /mcp responds with HTTP 405 because SSE is unsupported;
POST /mcp processes stateless JSON-RPC calls. Insufficient OAuth scopes on
an enabled tool produce HTTP 403 with a required-scope challenge.
