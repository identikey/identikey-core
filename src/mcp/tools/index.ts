/**
 * MCP Tools Registration
 *
 * Exports registration functions for all MCP tools.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { UserService } from '../../lib/keycloak/services/users';
import { registerUserTools } from './users';

export { registerUserTools } from './users';

/**
 * Register all available MCP tools on the server
 */
export function registerAllTools(
	server: McpServer,
	services: {
		userService: UserService;
	}
): void {
	registerUserTools(server, services.userService);
	// Future: registerAppTools, registerGuildTools, etc.
}
