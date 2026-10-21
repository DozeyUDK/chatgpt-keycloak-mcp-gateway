# Access control: Keycloak + host-managed policy

This template implements **two independent authorization layers**:

1. Keycloak authenticates the user and issues a signed OAuth access token with
   scopes, realm/client roles and optionally group membership.
2. MCP enforces the host-owned policy, approved tool list and filesystem mounts.
   Even a Keycloak administrator role cannot override a disabled local feature.

## Scope, role and group are not interchangeable

- OAuth scope: mcp:read is required for MCP login and read-only tools.
- OAuth scope: mcp:write is additionally required for fs_write.
- Realm role: read from the JWT realm_access.roles.
- Client role: read ONLY from resource_access[client_id].roles, with client_id
  set by the administrator in policy.json.
- Group: a top-level signed JWT groups array, such as ["/ai-writers"], produced
  by a Keycloak Group Membership mapper on the ACCESS TOKEN.
- Roles and groups determine membership in an authorization rule; they do not
  silently grant missing OAuth scopes.
- Rule semantics: ALL required_scopes and ANY listed role OR listed group.
  Privileged tools with neither required role nor required group fail closed.

The application does NOT call the Keycloak administrative API, and does not
allow the AI to edit its own roles or the Keycloak configuration.

## Configuration

The tracked config/policy.example.json provides the complete sample.

Example excerpt:

    "capabilities": {
      "WRITE_AND_ACCESS": false,
      "READ_ACCESS": false,
      "INSPECT_PERMISSIONS": true
    },
    "filesystem": {
      "READABLE_ROOTS": [],
      "EDITABLE_ROOTS": [],
      "max_read_bytes": 65536,
      "max_write_bytes": 65536
    }

To enable an example write tool, an administrator must ALSO:

- Enable tools.fs_write.enabled in the policy.
- Set filesystem.EDITABLE_ROOTS to existing absolute paths inside the container
  such as /workspace/projects.
- Grant mcp:read and mcp:write OAuth scopes to the intended Keycloak client,
  and give the user or group mcp-writer or /ai-writers respectively.
- Bind-mount exactly the approved host paths into /workspace/projects as RW
  on the MCP container. The policy alone never creates a mount.
- Ensure the container UID can write the mounted directory.

An example rule:

    "fs_write": {
      "enabled": true,
      "required_scopes": ["mcp:read", "mcp:write"],
      "any_roles": ["mcp-writer"],
      "any_groups": ["/ai-writers"]
    }

A role or group grant is an OR. An agent still needs both OAuth scopes.
No shell, Docker socket or generic host command execution is implemented.

## Securing the policy file

**Do not use the sample policy file inside ChatGPT_Editable as production
policy.** This development tree is writable by other AI tools.

Instead, create a standalone, administrator-owned file OUTSIDE every writable
root of every connector and mount it read-only in the MCP container.

For example, on the host (admin action):

    sudo install -d -o root -g root -m 0755 /srv/mcp-policy
    sudo install -o root -g root -m 0444 config/policy.example.json /srv/mcp-policy/policy.json

Set MCP_POLICY_HOST_FILE=/srv/mcp-policy/policy.json in the private .env file.
The included Compose file bind-mounts this file read-only to
/etc/mcp/policy.json and refuses to auto-create a missing host path.

An administrator can edit their private policy then restart the service.
No MCP tool can modify the live policy through the permissions interface.
Make sure no other MCP tool can access the host policy directory either.

Do NOT mount the entire host home directory, Keycloak secrets or the Docker
socket into the MCP container. Do NOT put live config into any READABLE_ROOTS
or EDITABLE_ROOTS. Production runtime policies are held out of this public repo.

## Agent-visible introspection

With INSPECT_PERMISSIONS=true and the permissions_inspect tool enabled,
an authenticated agent can discover the effective status of each feature and
a textual note explaining how an administrator can unlock it. For example:

    {
      "policy_version": 1,
      "capabilities": {
        "fs_write": {
          "available": false,
          "admin_action_if_disabled":
            "Admin: set WRITE_AND_ACCESS=true, EDITABLE_ROOTS, tools.fs_write.enabled; grant mcp:write and its role/group; mount approved roots RW."
        }
      },
      "policy_managed_outside_agent": true
    }

This excerpt is illustrative; the real introspection response also includes
the other tools. It does NOT reveal exact root paths or token/group details.
Tool calls are authorized server-side *each time*, not only during tools/list.

The policy loads once on service startup. Restart is required to apply changes.
Existing signed tokens retain prior role/scope claims until they expire; use
short token TTLs or a separate audited revocation/introspection mechanism for
rapid privilege removal.

## MCP tool audit

Every authenticated `tools/call` emits a structured allow/deny audit event.
The log includes the selected tool, decision/reason and pseudonymous subject
identifier. File paths are hashed and file contents are never logged. Read
[Threat Model](THREAT_MODEL.md) for prompt-injection, confused-deputy,
retention and revocation limitations.

## File operation safety

fs_read/fs_write are disabled by default. When enabled:

- Accept only normalized absolute paths inside configured existing roots.
- Use no-follow directory and file descriptors to reject symlink traversal.
- Reject traversal, .git, .env, policy.json and several sensitive path names.
- Atomic writes replace targets without modifying hardlinked source content.
- File sizes are bounded. No delete, execute, chmod, shell or list-tree tool.
- Runtime OS permissions and exact mount limits remain mandatory.

Before production, complete an independent security review and E2E testing.
