# Keycloak configuration notes (example only)

**Never commit a full production realm export.** Use a throwaway realm.

1. Create a realm such as `demo`, accessible at
   `https://auth.example.com/realms/demo`. The exact issuer in access tokens
   must match `KEYCLOAK_ISSUER`.
2. Register an OAuth client for ChatGPT. Prefer authorization code, public
   client, PKCE S256 required. Restrict web origins and redirect URIs to
   values ChatGPT actually displays for this connection. Never use '*'.
3. Provision the OAuth scope `mcp:read` as a scope **present in the access
   token's scope claim**. A Keycloak role with the same name does not count.
4. Configure an audience protocol mapper so the **access** token has the
   exact `KEYCLOAK_AUDIENCE` (prefer the canonical resource URI, e.g. `https://mcp.example.com/mcp`).
5. Obtain an access token with the actual OAuth flow and verify claims
   `iss`, `aud`, `exp`, `scope`, `typ`. Avoid exposing the token to
   logs, screenshots or public issue threads.
6. Keycloak publishes OIDC discovery at
   `<issuer>/.well-known/openid-configuration`, including `jwks_uri`.
   This example requires JWKS at the *same HTTPS origin* as the issuer.
7. The resource server advertises `authorization_servers` in the RFC 9728
   protected-resource metadata and verifies tokens locally.

### ChatGPT client registration

A standard Keycloak deployment can reject ChatGPT's Client ID Metadata
Document (CIMD). Read the current Keycloak guide before deployment:
https://www.keycloak.org/securing-apps/mcp-authz-server

This repository does not include Keycloak client-policy plug-ins, DCR shims,
token relays or invented registration endpoints. Those require independent
implementation and review if needed.

### Negative checks

- Wrong `aud`: 401
- Wrong `iss`: 401
- Invalid or expired JWT: 401
- Missing `mcp:read` scope: 403
- Scope-like Keycloak role only: 403
- Keycloak discovery/JWKS unavailable: 503 (fail-closed)
