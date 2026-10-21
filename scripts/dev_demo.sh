#!/usr/bin/env bash
# One-command disposable local identity provider + MCP integration demo.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker and Docker Compose v2 are required; no services started." >&2
  exit 2
fi

echo "Launching a DEV-ONLY, private Keycloak realm and MCP server..."
echo "The demo does not expose ports on the host and cannot authenticate ChatGPT directly."
docker compose -f docker-compose.dev.yml up --build --wait -d mcp-gateway

echo "Checking a real Keycloak-issued access token against the MCP endpoint..."
docker compose -f docker-compose.dev.yml --profile smoke run --build --rm smoke

echo "Demo succeeded. Tear it down when finished:"
echo "  docker compose -f docker-compose.dev.yml down -v --remove-orphans"
