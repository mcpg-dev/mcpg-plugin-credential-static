# Static Credential Issuer — `dev.mcpg.credential.static`

> class `credential_issuer` · `native` · package `mcpg-plugin-credential-static` · artifact `libmcpg_plugin_credential_static.so` · Apache-2.0

Hands out operator-declared credentials to gateway backends without any external
secret infrastructure. You name a set of targets in config — each holding either
a single value such as a bearer token, or a set of named parts such as a
username and password — and backends reference them by
`cred://dev.mcpg.credential.static/<target>` rather than embedding the secret in
their own binding. Each target carries an authorization rule, so a shared
gateway can hand different targets to different callers. It performs no outbound
network calls at all. Reach for it for development, lab, and partner
integrations, or wherever the credential is genuinely static and a dynamic
issuer would be overkill.

## What it does
- Resolves `cred://dev.mcpg.credential.static/<target>` to the configured value,
  and `cred://dev.mcpg.credential.static/<target>#<part>` to a named part.
- Serves either a single `value` or a `parts` map per target — exactly one of
  the two, enforced at config load.
- Authorizes each issuance against the caller's identity using the target's
  `authorize` rule; a caller that does not match gets a `NotAuthorized` error
  rather than the secret.
- Reports `ttl_seconds` so the gateway's credential cache evicts on the schedule
  you choose per target.
- Attaches the target's free-form `metadata` to the issued credential, where it
  reaches audit and observability without being part of the secret.
- Declares no required capabilities: it never opens a socket, reads a file, or
  calls a host service.

## Configuration
Loaded from the flat top-level `plugins:` list; bindings then select a target per
credential reference through a `cred://` URI.

```yaml
plugins:
  - id: dev.mcpg.credential.static
    class: credential_issuer
    source: { path: ./plugins/libmcpg_plugin_credential_static.so }
    config:
      targets:
        orders-api:                      # → cred://dev.mcpg.credential.static/orders-api
          value: ${env.ORDERS_API_TOKEN}
          ttl_seconds: 3600
          authorize: { kind: roles, roles: ["service"] }
          metadata: { owner: platform-team }
        orders-pg:                       # → …/orders-pg#username, …/orders-pg#password
          parts:
            username: orders_ro
            password: ${env.ORDERS_PG_PASSWORD}
          ttl_seconds: 600
          authorize: { kind: any }
```

| Field | Type | Default | Description |
|---|---|---|---|
| `targets` | map<string, target> | — (required) | Target name to target entry; must be non-empty. |

Each entry under `targets`:

| Field | Type | Default | Description |
|---|---|---|---|
| `value` | string? | `null` | Single-value credential. Mutually exclusive with `parts`. |
| `parts` | map<string,string> | `{}` | Named parts, each addressable as `#<part>`. Mutually exclusive with `value`. |
| `ttl_seconds` | u64 | `3600` | Cache lifetime the gateway applies to the issued credential; must be > 0. |
| `authorize` | object | `{ kind: any }` | Identity rule; see below. |
| `metadata` | map<string,string> | `{}` | Free-form metadata surfaced on the issued credential. |

Unknown fields are rejected. Every target must set exactly one of `value` or
`parts`, and an `authorize` rule with an empty list is rejected — a config that
fails validation aborts the plugin's registration instead of loading a
half-working credential issuer.

## Security
The `authorize` rule is evaluated on every issuance against the caller identity
the gateway's identity chain produced:

| `kind` | Passes when |
|---|---|
| `any` | The caller reaches at least `header_asserted` trust. An anonymous caller never qualifies. |
| `roles` | The caller is at `verified` trust **and** holds one of the listed roles. |
| `groups` | The caller is at `verified` trust **and** belongs to one of the listed groups. |
| `subjects` | The caller is at `verified` trust **and** its subject id is in the allowlist. |

The `verified` floor on the identity-derived rules is deliberate: at
`header_asserted` trust the subject comes from a client-supplied header and the
role and group sets are empty, so a forged header would otherwise match a subject
allowlist and lift another principal's credential.

Keep secrets out of the config artifact by writing `${env.VAR}` and letting the
gateway's secret resolver fill them in at load time.

## Build
`cdylib-export` is enabled by default, so the plain build already produces the
loadable artifact. Disable the default features when linking this crate as an
rlib path dependency alongside other plugins, so the build does not emit two
`mcpg_plugin_register` exports.

```bash
cargo build -p mcpg-plugin-credential-static --features cdylib-export --release   # → target/release/libmcpg_plugin_credential_static.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes and the ABI: <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Dynamic alternatives: `libs/plugins/credential/vault-dynamic-db`,
  `libs/plugins/credential/oauth-client-credentials`, `libs/plugins/credential/aws-sts`
