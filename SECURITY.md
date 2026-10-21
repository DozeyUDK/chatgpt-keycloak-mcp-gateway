# Security policy and pre-publication checklist

This repository is an **example** and has not received an external security
audit. Submit vulnerability reports privately to the maintainer, not as public
issues containing secrets.

## Before creating a PUBLIC GitHub repository

- [ ] Confirm source consists solely of hand-selected template files;
      **never run `git add -A` inside a production configuration tree**.
- [ ] Inspect all files for hostnames, public/private IP addresses, domains,
      account names, SSH usernames, filesystem topology and email addresses.
- [ ] Confirm no Keycloak clients' secrets, tunnel tokens, JWTs, cookies,
      private keys, `.env` files, credentials, backups or log exports.
- [ ] Run `python scripts/security_check.py`, Gitleaks and TruffleHog.
      The included scanner is only a **basic tripwire**, not sufficient alone.
- [ ] Use a fresh git repository. Inspect `git log --all -p`, not just HEAD.
- [ ] Ensure public GitHub Actions have least-privilege permissions.
- [ ] Run `python -m pytest -q` plus dependency scanning.
- [ ] Run end-to-end tests against a throwaway Keycloak realm, a throwaway
      ChatGPT connector, and a throwaway Cloudflare hostname.
- [ ] Review exact Keycloak redirect URIs, PKCE S256, issuer/aud/scope,
      access-token lifetime, JWKS rotation and token audience mapping.
- [ ] Do not allow shell/Docker/SSH tools without per-action authorization,
      allowlists, audit trails and separate privilege boundaries.

## Deployment warnings

- Keep port 8000 internal; terminate public HTTPS at a trusted proxy.
- Do not route unauthenticated users to privileged internal services.
- Keep the live policy outside every AI-writable root, owned by an administrator,
  and bind-mounted :ro; do not serve it from ChatGPT_Editable.
- OAuth scopes, Keycloak roles/groups and host policy are independent grants;
  disabling any one must prevent privileged access.
- Do not configure Cloudflare Access in a way that blocks OAuth discovery or
  ChatGPT's authorization flow; apply narrowly scoped WAF exceptions only
  where actually required.
- Do not disable JWT audience checks, accept unsigned/HS tokens, or grant
  OAuth scopes based on Keycloak roles.
- A deployment must constrain egress from this service (including OIDC/JWKS
  requests) to the trusted identity provider.
- Stateless transport and minimal method set here do not cover all current
  MCP features; require a full interoperability review before production use.
