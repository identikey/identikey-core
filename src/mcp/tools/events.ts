import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { EventBus } from '../../lib/events/bus';

const EventSchema = z.object({
	id: z.string(),
	timestamp: z.number(),
	source: z.string(),
	category: z.string(),
	type: z.string(),
	severity: z.string(),
	userId: z.string().optional(),
	clientId: z.string().optional(),
	ipAddress: z.string().optional(),
	details: z.record(z.string()),
	error: z.string().optional()
});

export function registerEventTools(server: McpServer, eventBus: EventBus): void {
	server.registerTool(
		'search_events',
		{
			title: 'Search Events',
			description:
				'Search Keycloak events with filters. Returns login events (LOGIN, LOGIN_ERROR, REGISTER, etc.) and admin events (CREATE, UPDATE, DELETE of resources).',
			inputSchema: {
				type: z
					.string()
					.optional()
					.describe('Event type filter (e.g. LOGIN, LOGIN_ERROR, UPDATE:CLIENT)'),
				clientId: z.string().optional().describe('Filter by client ID'),
				userId: z.string().optional().describe('Filter by user ID'),
				category: z
					.enum(['auth', 'admin'])
					.optional()
					.describe('Filter by category: auth (login events) or admin (config changes)'),
				severity: z
					.enum(['info', 'warn', 'error'])
					.optional()
					.describe('Filter by severity'),
				max: z.number().optional().describe('Maximum results (default 50)')
			},
			outputSchema: {
				events: z.array(EventSchema),
				count: z.number()
			}
		},
		async ({ type, clientId, userId, category, severity, max }) => {
			try {
				const events = await eventBus.query({
					type,
					clientId,
					userId,
					category,
					severity,
					max
				});
				const output = { events, count: events.length };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return {
					content: [
						{
							type: 'text',
							text: `Error searching events: ${(error as Error).message}`
						}
					],
					isError: true
				};
			}
		}
	);

	server.registerTool(
		'get_recent_events',
		{
			title: 'Get Recent Events',
			description:
				'Get the N most recent events, optionally filtered by client. Useful for checking recent login activity or errors.',
			inputSchema: {
				clientId: z.string().optional().describe('Filter by client ID'),
				max: z.number().optional().describe('Number of events to return (default 20)')
			},
			outputSchema: {
				events: z.array(EventSchema),
				count: z.number()
			}
		},
		async ({ clientId, max }) => {
			try {
				const events = await eventBus.query({ clientId, max: max ?? 20 });
				const output = { events, count: events.length };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return {
					content: [
						{
							type: 'text',
							text: `Error fetching recent events: ${(error as Error).message}`
						}
					],
					isError: true
				};
			}
		}
	);
}
