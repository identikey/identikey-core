/**
 * MCP Tools Registration
 *
 * Exports registration functions for all MCP tools.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { UserService } from '../../lib/keycloak/services/users';
import type { AuthFlowService } from '../../lib/keycloak/services/auth-flows';
import type { EventBus } from '../../lib/events/bus';
import { registerUserTools } from './users';
import { registerAuthFlowTools } from './auth-flows';
import { registerEventTools } from './events';

export { registerUserTools } from './users';
export { registerAuthFlowTools } from './auth-flows';
export { registerEventTools } from './events';

/**
 * Register all available MCP tools on the server
 */
export function registerAllTools(
	server: McpServer,
	services: {
		userService: UserService;
		authFlowService: AuthFlowService;
		eventBus: EventBus;
	}
): void {
	registerUserTools(server, services.userService);
	registerAuthFlowTools(server, services.authFlowService);
	registerEventTools(server, services.eventBus);
}
