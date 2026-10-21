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
    |-- demo_ping only
    |
    +-- HTTPS OIDC discovery and JWKS -> Keycloak realm

The code never exposes a Keycloak administrative API and never writes to the
real host. The verified access token's scope is used to authorize read-only
demo tooling only. For any new tool, introduce explicit per-tool authorization,
separate capabilities, execution timeouts and audit logging.

Note: OAuth client registration and token issuance happen entirely at the
authorization server. Resource-server metadata is NOT authorization-server
metadata. This project does not impersonate Keycloak.

## Protocol scope

The demonstration uses JSON-RPC 2.0 responses for simple MCP requests over
HTTP POST. It is stateless and does not support server-side event streaming,
resumability, subscriptions, or session IDs. It is not a drop-in substitute
for a complete MCP SDK transport implementation.

The HTTP transport validates the optional Origin and MCP-Protocol-Version
headers. Browser client origins must be explicitly approved in
MCP_ALLOWED_ORIGINS. Clients that omit Origin use bearer authentication.
Authenticated GET /mcp responds with HTTP 405 because SSE is unsupported;
POST /mcp processes stateless JSON-RPC calls. Insufficient OAuth scopes on
an enabled tool produce HTTP 403 with a required-scope challenge.
