# One-command local Keycloak + MCP integration demo

This dev stack is a reproducible, **isolated OAuth resource-server integration
test**, not a public ChatGPT-ready deployment. It automatically downloads
Keycloak, imports an example realm, generates an ephemeral HTTPS certificate,
starts the MCP server and calls an MCP tool with a real token issued by Keycloak.

## Requirements

- Linux/macOS with Docker Engine or compatible runtime, **Docker Compose v2**
  and enough RAM for a 1 GiB Keycloak container.
- Available internet access to download `quay.io/keycloak/keycloak:26.8.1`
  and Docker build dependencies.
- No existing Keycloak installation or production credentials required.

## Start, verify, clean up

```bash
git clone https://github.com/DozeyUDK/chatgpt-keycloak-mcp-gateway.git
cd chatgpt-keycloak-mcp-gateway
bash scripts/dev_demo.sh
```

The script runs `docker compose -f docker-compose.dev.yml up --build --force-recreate --wait -d
mcp-gateway`, then a disposable smoke client. The client:

1. Requests `client_credentials` token from a real local Keycloak realm.
2. Sends `initialize`, `tools/list`, `demo_ping` and `permissions_inspect`.
3. Verifies that invalid JWTs are rejected and `fs_write` remains disabled.

Everything communicates over a **private Docker network**. Neither Keycloak,
its admin console, nor MCP are mapped to a host port. All credentials in the
example realm are **intentionally public development placeholders**, not
production secrets. Never reuse this realm, credentials, or self-signed
certificate for publicly reachable services.

To remove demo containers and TLS volume:

```bash
docker compose -f docker-compose.dev.yml down -v --remove-orphans
```

This is intentionally an ephemeral demo: deleting/recreating the Keycloak
container may reimport the realm, and `down -v` removes the TLS certificate.

## What this does not set up

- A public HTTPS endpoint for ChatGPT, or external DNS/tunnel.
- An interactive ChatGPT user authorization flow: the smoke test uses an
  isolated client-credentials client, not the ChatGPT OAuth client.
- A ChatGPT CIMD compatibility extension for Keycloak.
- Real writable MCP filesystem mounts, production identities, or a
  production database.

These are distinct deployment tasks. See [Keycloak setup](KEYCLOAK_SETUP.md),
[Access Policy](ACCESS_POLICY.md), and the sanitized
[ChatGPT connection example](../README.md#chatgpt-connection-fields-example).

## Security notes

- Keycloak is started using `start-dev` and its local development database.
  **Do not use this compose file for production.**
- The fixture's known demo client secret is safe only because services have
  no published ports and the entire environment is disposable.
- The temporary TLS certificate trusts only hostname `keycloak`; it is not
  a substitute for a public CA certificate and hostname.
- Do not mix this Compose project with your real Keycloak stack. The
  dedicated project name is `keycloak-mcp-demo`.
