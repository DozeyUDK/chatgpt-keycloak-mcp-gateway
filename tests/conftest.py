"""Only public fictitious example values are injected for import-time app setup."""
import os

os.environ.setdefault("MCP_PUBLIC_URL", "https://mcp.example.com/mcp")
os.environ.setdefault("KEYCLOAK_ISSUER", "https://auth.example.com/realms/demo")
os.environ.setdefault("KEYCLOAK_AUDIENCE", "mcp-api")
