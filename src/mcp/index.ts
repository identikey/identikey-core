import { config as loadEnv } from 'dotenv';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { loadConfig } from '../lib/keycloak/config';
import { validateConnection } from '../lib/keycloak/client';

async function main() {
	// Load environment variables for local development
	if (!process.env.KEYCLOAK_URL) {
		try {
			loadEnv();
		} catch {
			// ignore if dotenv is not available; production may inject env vars differently
		}
	}

	try {
		loadConfig();
	} catch (error) {
		// eslint-disable-next-line no-console
		console.error('Failed to load Keycloak configuration:', (error as Error).message);
		process.exit(1);
	}

	try {
		await validateConnection();
	} catch (error) {
		// validateConnection already logs structured diagnostics via logger
		// Surface a concise message for the operator and exit non-zero.
		const message = (error as Error).message || 'Keycloak connection validation failed';
		// eslint-disable-line no-console
		console.error(`Connection validation failed: ${message}`);
		process.exit(1);
	}

	const server = new McpServer({
		name: 'keycloak-commander',
		version: '0.1.0'
	});

	// TODO (Epic 2+): register MCP tools from ./tools/*

	const transport = new StdioServerTransport();
	await server.connect(transport);
}

void main().catch((error) => {
	// eslint-disable-next-line no-console
	console.error('Fatal error starting keycloak-commander MCP server:', error);
	process.exit(1);
});
