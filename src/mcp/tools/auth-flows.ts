/**
 * Auth Flow MCP Tools
 *
 * Exposes AuthFlowService operations as MCP tools for AI agents.
 * Tools are thin wrappers that delegate to AuthFlowService and format responses.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AuthFlowService } from '../../lib/keycloak/services/auth-flows';
import { IdentiKeyError } from '../../lib/keycloak/errors';

// Zod schemas for output types
const LoginFlowSchema = z.object({
	id: z.string(),
	alias: z.string(),
	description: z.string().optional(),
	providerId: z.string(),
	topLevel: z.boolean(),
	builtIn: z.boolean()
});

const FlowExecutionSchema = z.object({
	id: z.string(),
	displayName: z.string(),
	requirement: z.enum(['REQUIRED', 'ALTERNATIVE', 'CONDITIONAL', 'DISABLED']),
	configurable: z.boolean(),
	providerId: z.string().optional(),
	level: z.number(),
	index: z.number(),
	authenticationFlow: z.boolean()
});

/**
 * Format an error for MCP response with actionable context
 */
function formatError(
	error: unknown,
	context: Record<string, unknown>
): {
	content: Array<{ type: 'text'; text: string }>;
	isError: true;
} {
	const err = error instanceof IdentiKeyError ? error : new Error(String(error));
	const code = error instanceof IdentiKeyError ? error.code : 'UNKNOWN_ERROR';
	const message = err.message;

	const contextStr = Object.entries(context)
		.map(([k, v]) => `${k}: ${v}`)
		.join(', ');

	return {
		content: [
			{
				type: 'text',
				text: `Error [${code}]: ${message}\nContext: ${contextStr}`
			}
		],
		isError: true
	};
}

/**
 * Register all auth flow MCP tools on the server
 */
export function registerAuthFlowTools(server: McpServer, authFlowService: AuthFlowService): void {
	// list_login_flows - List all authentication flows (FR34)
	server.registerTool(
		'list_login_flows',
		{
			title: 'List Login Flows',
			description: 'List all authentication flows in the realm. Returns built-in and custom flows.',
			inputSchema: {},
			outputSchema: {
				flows: z.array(LoginFlowSchema),
				count: z.number()
			}
		},
		async () => {
			try {
				const flows = await authFlowService.list();
				const output = { flows, count: flows.length };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'list_login_flows' });
			}
		}
	);

	// get_login_flow - Get flow details by alias (FR35)
	server.registerTool(
		'get_login_flow',
		{
			title: 'Get Login Flow',
			description: 'Get detailed information for a specific authentication flow by alias.',
			inputSchema: {
				flowAlias: z
					.string()
					.describe('Flow alias (e.g., "browser", "direct grant", "registration")')
			},
			outputSchema: {
				flow: LoginFlowSchema
			}
		},
		async ({ flowAlias }) => {
			try {
				const flow = await authFlowService.get(flowAlias);
				const output = { flow };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'get_login_flow', flowAlias });
			}
		}
	);

	// list_flow_executions - List executions (steps) within a flow (FR36)
	server.registerTool(
		'list_flow_executions',
		{
			title: 'List Flow Executions',
			description:
				'List all executions (steps) within an authentication flow. Shows the hierarchy of authenticators.',
			inputSchema: {
				flowAlias: z.string().describe('Flow alias to list executions for')
			},
			outputSchema: {
				flowAlias: z.string(),
				executions: z.array(FlowExecutionSchema),
				count: z.number()
			}
		},
		async ({ flowAlias }) => {
			try {
				const executions = await authFlowService.listExecutions(flowAlias);
				const output = { flowAlias, executions, count: executions.length };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'list_flow_executions', flowAlias });
			}
		}
	);

	// copy_login_flow - Copy a flow to create a new one (FR40)
	server.registerTool(
		'copy_login_flow',
		{
			title: 'Copy Login Flow',
			description:
				'Create a copy of an existing authentication flow. Useful for customizing built-in flows (which cannot be modified directly).',
			inputSchema: {
				sourceAlias: z.string().describe('Alias of the flow to copy'),
				newAlias: z.string().describe('Alias for the new flow')
			},
			outputSchema: {
				flow: LoginFlowSchema,
				copiedFrom: z.string()
			}
		},
		async ({ sourceAlias, newAlias }) => {
			try {
				const flow = await authFlowService.copy(sourceAlias, newAlias);
				const output = { flow, copiedFrom: sourceAlias };
				return {
					content: [
						{
							type: 'text',
							text: `Created flow "${newAlias}" as copy of "${sourceAlias}"`
						},
						{ type: 'text', text: JSON.stringify(output, null, 2) }
					],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'copy_login_flow', sourceAlias, newAlias });
			}
		}
	);
}
