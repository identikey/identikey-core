# IdentiKey Core

The identity platform core for IdentiKey — providing native mobile authentication, JWT token issuance, passkey management, and Keycloak integration for user storage.

## Architecture Overview

IdentiKey Core serves as the **identity layer** for the IdentiKey platform:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Mobile/Native Apps                          │
│               (Apple/Google Sign In, Passkeys)                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    IdentiKey Core                               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Auth Endpoints: /apple-provision, /google-provision,       ││
│  │                 /passkey-*, /token/*                        ││
│  │ JWT Signing: ES256, JWKS, Token Introspection              ││
│  │ WebAuthn: Passkey Registration & Authentication            ││
│  │ Device Trust: Master vs Temporary Devices                  ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Admin Layer (CLI + MCP)                                    ││
│  │ User management, debugging, configuration                  ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Keycloak (User Store + Credentials)           │
│  Users, Passkeys, Groups/Guilds, Roles, Standard OIDC for Web  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **IdentiKey issues its own JWTs** for mobile/native auth (no Keycloak preview features needed)
2. **Social login as bootstrap** — Apple/Google for one-time identity verification, then passkey enrollment
3. **Passkeys for ongoing auth** — FIDO2/WebAuthn, stored in Keycloak credentials (works for mobile & web)
4. **Keycloak for user storage** — Admin API for CRUD, standard OIDC still works for web apps
5. **Device trust model** — Master devices (with passkeys) vs temporary devices (short-lived tokens)

## Prerequisites

- [Bun](https://bun.sh/) runtime
- Access to a Keycloak instance with admin credentials
- PostgreSQL database (for devices, challenges, refresh tokens)

## Installation

```bash
bun install
```

## Configuration

Create a `.env` file:

```env
# Keycloak Admin API
KEYCLOAK_URL=https://auth.identikey.io
KEYCLOAK_REALM=identikey
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_CLIENT_SECRET=your-client-secret

# IdentiKey Token Signing
IDENTIKEY_ISSUER=https://connect.identikey.io
IDENTIKEY_SIGNING_KEY_PATH=/path/to/private-key.pem
# Or use environment variable for the key itself
IDENTIKEY_SIGNING_KEY=-----BEGIN EC PRIVATE KEY-----...

# Bootstrap Verification (Social Login)
APPLE_SERVICES_ID=ai.morphist.app
GOOGLE_CLIENT_ID=your-google-oauth-client-id

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/identikey

LOG_LEVEL=info
```

## Admin CLI

The CLI provides administrative access to IdentiKey:

```bash
# Run via npm script
bun run cli users list
bun run cli users --help

# Or install globally as `kc`
bun link

# User management
kc users list
kc users list --search "john"
kc users get <user-id>
kc users create --username newuser --email user@example.com
kc users update <user-id> --firstName John
kc users delete <user-id>
kc users reset-password <user-id> --password "newpass" --temporary
kc users credentials <user-id>

# Auth flow inspection (for debugging)
kc auth-flows list
kc auth-flows executions <flow-alias>
```

All commands support `--json` for machine-readable output.

## MCP Server

Run the MCP server for AI agent integration:

```bash
bun run mcp
```

Add to your MCP client config (e.g., Cursor):

```json
{
	"mcpServers": {
		"identikey": {
			"command": "bun",
			"args": ["run", "mcp"],
			"cwd": "/path/to/identikey-core"
		}
	}
}
```

Available MCP tools:
- `list_users`, `get_user`, `create_user`, `update_user`, `delete_user`
- `reset_user_password`, `get_user_credentials`, `delete_user_credential`
- `list_login_flows`, `get_login_flow`, `list_flow_executions`

## Auth Endpoints (Coming Soon)

Native mobile authentication endpoints:

| Endpoint | Purpose |
|----------|---------|
| `POST /apple-provision` | Verify Apple token, create user, return WebAuthn challenge |
| `POST /google-provision` | Verify Google token, create user, return WebAuthn challenge |
| `POST /passkey-register` | Store passkey in Keycloak, issue tokens |
| `POST /passkey-auth/start` | Return authentication challenge |
| `POST /passkey-auth/finish` | Verify assertion, issue tokens |
| `POST /token/refresh` | Refresh access token |
| `POST /token/revoke` | Revoke refresh token(s) |
| `POST /device-authorize` | QR-based temporary device auth |
| `GET /.well-known/jwks.json` | Public keys for token validation |
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `POST /introspect` | Token validation for resource servers |

## Development

```bash
bun run dev          # SvelteKit dev server
bun run test:unit    # Unit tests
bun run test:e2e     # E2E tests
bun run test         # All tests
bun run lint         # Linting
bun run format       # Formatting
```

## Project Structure

```
identikey-core/
├── src/
│   ├── lib/
│   │   ├── keycloak/           # Keycloak Admin API wrapper
│   │   │   ├── client.ts       # Authenticated client
│   │   │   ├── config.ts       # Configuration
│   │   │   ├── errors.ts       # Error types
│   │   │   ├── services/       # Domain services (users, auth-flows)
│   │   │   └── mappers/        # Keycloak → IdentiKey type mapping
│   │   ├── auth/               # (New) Auth endpoints
│   │   │   ├── jwt.ts          # Token signing/verification
│   │   │   ├── apple.ts        # Apple token verification
│   │   │   ├── webauthn.ts     # Passkey registration/auth
│   │   │   └── device.ts       # Device trust management
│   │   └── server/
│   │       ├── auth.ts
│   │       └── db/
│   ├── mcp/                    # MCP server for AI agents
│   ├── cli/                    # CLI commands
│   └── routes/                 # SvelteKit routes (future web UI)
├── docs/
│   ├── prd.md
│   ├── architecture.md
│   ├── epics.md
│   └── identikey-apple-auth-architecture-analysis.md
└── ...
```

## Documentation

- [PRD](docs/prd.md) — Product requirements
- [Architecture](docs/architecture.md) — Technical design
- [Epics](docs/epics.md) — Implementation breakdown
- [Apple Auth Analysis](docs/identikey-apple-auth-architecture-analysis.md) — Native auth architecture

## License

Private — IdentiKey Platform
