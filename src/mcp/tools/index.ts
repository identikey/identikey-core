/**
 * MCP Tools Registration
 *
 * Exports registration functions for all MCP tools.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { UserService } from '../../lib/keycloak/services/users';
import type { AuthFlowService } from '../../lib/keycloak/services/auth-flows';
import { registerUserTools } from './users';
import { registerAuthFlowTools } from './auth-flows';

export { registerUserTools } from './users';
export { registerAuthFlowTools } from './auth-flows';

/**
 * Register all available MCP tools on the server
 */
export function registerAllTools(
	server: McpServer,
	services: {
		userService: UserService;
		authFlowService: AuthFlowService;
	}
): void {
	registerUserTools(server, services.userService);
	registerAuthFlowTools(server, services.authFlowService);
	// Future: registerAppTools, registerGuildTools, etc.
}
