# Threat model and security boundaries

This public repository is a minimal **Keycloak-protected MCP resource server**.
It is not an audited sandbox for arbitrary AI-generated commands and does not
include the ChatGPT/Keycloak client-registration compatibility adapter.

## Trust boundaries

| Actor / input | Trust level | Enforcement |
|---|---|---|
| Remote MCP client, including AI tool arguments | Untrusted | JWT, strict tool schema, scope + role/group + host policy |
| Files retrieved by tools (including project source / README) | Untrusted | Content is data, never authorization |
| Keycloak-signed access token | Authenticated, but not intrinsically authorized | Audience, issuer, expiry, scope and role/group checks |
| Host-managed policy file | Trusted administrator input | Outside writable roots, read-only bind mount |
| Filesystem bind mounts / UID | Independent host-level security boundary | Mount only approved paths, no Docker socket |

## Prompt injection / confused deputy

A model may read untrusted source code, an issue, or a README containing
instructions to call another MCP tool. Such instructions do NOT represent an
authorization decision by the human user. An attacker can exploit this to
make an authorized AI agent perform an unintended write **inside otherwise
permitted roots**. Keycloak only establishes identity and configured permissions;
it cannot determine the human's actual intent.

**Current controls:** tools are off by default; file writes need explicit
admin policy, OAuth mcp:write scope, matching role/group, approved mount, OS
access, per-request checks and a size bound. No shell, Docker socket, chmod,
delete, or arbitrary command tool exists. Audit events include the chosen
tool and the policy decision, but exclude raw tool arguments.

**What is NOT solved:** the server does not distinguish an intentional human
request from an AI response to hostile text. If write access is enabled,
a prompt injection could still modify an authorized file. This repository has
no interactive per-write human approval, provenance tracking for model output,
semantic diff review, or content-based DLP enforcement.

**Mitigation for deployers:** keep the AI read-only by default; enable writes
only to a disposable/worktree-style directory with minimal data; inspect diffs
and gate merges externally. Require human confirmation at the client/workflow
level before writes affecting production or critical source. Do not use
system-level roles/groups as a substitute for user intent.

## File and tool boundaries

- All paths must be absolute, normalized, and contained by an approved
  Path-relative root; never use a string prefix such as startswith("/workspace")
  to enforce paths.
- The fs_safe module traverses directories with directory descriptors and
  O_NOFOLLOW, rejects symlinks, applies file-size caps, and writes via
  atomic replacement in the parent directory.
- ACLs and Docker read/write mounts are the *final* enforcement boundary.
  The application does not defend against an unrelated privileged process
  changing host mounts, directory ownership, or the policy file.
- Host root and the policy path must not be inside any accessible root.
  Sensitive filenames are blocked as a defense in depth, not as a guarantee
  that every secret has been recognized.

## OAuth, token replay, and revocation

- Only audience-bound RS256 access tokens from the pinned HTTPS Keycloak issuer
  are accepted; missing required scopes fail closed.
- JWKS keys are cached with a bounded TTL. Previously unknown key IDs may
  trigger a refresh no more often than once per 30 seconds.
- Revoking a Keycloak role or group will not invalidate a JWT already
  issued until expiration. This stateless example does not call token
  introspection or implement immediate user/session revocation.
- Choose short access-token lifetimes and protect authorization/refresh tokens.
  Configure trusted proxy and service egress allowlists in the deployment.

## Audit and observability

Each authenticated MCP tools/call now generates a structured audit event:
subject fingerprint (not the raw subject), tool name, allow/deny decision,
reason and optional hashed path / content byte length. The logger intentionally
**never** records token values, raw paths, file contents, or unfiltered arguments.

Audit logs are written to stderr for the container log collector. They are not
tamper-evident, do not themselves implement a durable audit database and are
not guaranteed delivered when the logging infrastructure is unavailable.
Configure external retention, rotation, alerting, access controls and request
rate limiting at the ingress/proxy.

Do not enable raw-argument logging just to simplify debugging: MCP arguments
may contain secrets, customer data, or prompt injection payloads.

## Out of scope / planned before production use

1. A fresh Keycloak dev realm and integration test which obtains a **real**
   Keycloak access token, then calls initialize, tools/list and tools/call.
2. ChatGPT's CIMD client-registration compatibility for specific supported
   Keycloak versions, implemented and validated without weakening token checks.
3. Full Streamable HTTP conformance via the official MCP Python SDK, or a
   documented interoperability matrix justifying the custom subset.
4. Application-level approval for high-impact writes, integrity checks and
   data-exfiltration controls suitable for the deployment.
5. Documented production security audit, end-to-end identity-provider outage
   behavior, dependency scan and external audit log retention.
