# Keycloak Commander

A multi-interface administration tool for Keycloak, providing CLI, MCP (Model Context Protocol), and Web UI access to manage users, authentication flows, roles, and more.

## Prerequisites

- [Bun](https://bun.sh/) runtime
- Access to a Keycloak instance with admin credentials

## Installation

```bash
bun install
```

## Configuration

Create a `.env` file with your Keycloak connection details:

```env
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=master
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_CLIENT_SECRET=your-client-secret
```

## CLI Usage

### Run via npm script

```bash
bun run cli users list
bun run cli users --help
```

### Install globally as `kc`

Link the package to make `kc` available system-wide:

```bash
bun link
```

Then use from anywhere:

```bash
kc users list
kc users list --search "john"
kc users get <user-id>
kc users create --username newuser --email user@example.com
kc users update <user-id> --firstName John
kc users delete <user-id>
kc users reset-password <user-id> --password "newpass" --temporary
kc users credentials <user-id>
kc users credentials <user-id> --delete <credential-id>
```

### Output formats

All list/get commands support `--json` for machine-readable output:

```bash
kc users list --json
kc users get <user-id> --json
```

## MCP Server

Run the MCP server for AI agent integration:

```bash
bun run mcp
```

Add to your MCP client config (e.g., Cursor):

```json
{
	"mcpServers": {
		"keycloak-commander": {
			"command": "bun",
			"args": ["run", "mcp"],
			"cwd": "/path/to/keycloak-commander"
		}
	}
}
```

Available MCP tools:

- `list_users` - List users with optional search/pagination
- `get_user` - Get user details by ID
- `create_user` - Create a new user
- `update_user` - Update user attributes
- `delete_user` - Delete a user
- `reset_user_password` - Set user password
- `get_user_credentials` - List user credentials
- `delete_user_credential` - Remove a credential

## Web UI

```bash
bun run dev
```

## Development

### Testing

```bash
bun run test:unit      # Unit tests
bun run test:e2e       # E2E tests
bun run test           # All tests
```

### Linting & Formatting

```bash
bun run lint
bun run format
```

## Architecture

- `src/lib/keycloak/` - Core Keycloak client, services, types, and error handling
- `src/cli/` - CLI commands using citty
- `src/mcp/` - MCP server and tools
- `src/routes/` - SvelteKit web UI
- `docs/` - Project documentation and sprint artifacts
