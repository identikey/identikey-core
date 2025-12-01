/**
 * User MCP Tools
 *
 * Exposes UserService operations as MCP tools for AI agents.
 * Tools are thin wrappers that delegate to UserService and format responses.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { UserService } from '../../lib/keycloak/services/users';
import { IdentiKeyError } from '../../lib/keycloak/errors';

// Zod schemas for output types
const UserSchema = z.object({
	id: z.string(),
	username: z.string(),
	email: z.string().optional(),
	firstName: z.string().optional(),
	lastName: z.string().optional(),
	enabled: z.boolean(),
	guilds: z.array(z.string()),
	createdTimestamp: z.number().optional()
});

const CredentialSchema = z.object({
	id: z.string(),
	type: z.string(),
	userLabel: z.string().optional(),
	createdDate: z.number().optional()
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
 * Register all user MCP tools on the server
 */
export function registerUserTools(server: McpServer, userService: UserService): void {
	// list_users - List users with optional search and pagination (FR5, FR6)
	server.registerTool(
		'list_users',
		{
			title: 'List Users',
			description:
				'List all users with optional search filter. Searches by username, email, first name, or last name.',
			inputSchema: {
				search: z.string().optional().describe('Search query to filter users'),
				max: z.number().optional().describe('Maximum number of results (default 100)'),
				offset: z.number().optional().describe('Offset for pagination (default 0)')
			},
			outputSchema: {
				users: z.array(UserSchema),
				count: z.number()
			}
		},
		async ({ search, max, offset }) => {
			try {
				const users = search
					? await userService.search(search, { max, offset })
					: await userService.list({ max, offset });

				const output = { users, count: users.length };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'list_users', search, max, offset });
			}
		}
	);

	// get_user - Get user by ID (FR7)
	server.registerTool(
		'get_user',
		{
			title: 'Get User',
			description: 'Get detailed information for a specific user by ID.',
			inputSchema: {
				id: z.string().describe('User ID')
			},
			outputSchema: {
				user: UserSchema
			}
		},
		async ({ id }) => {
			try {
				const user = await userService.get(id);
				const output = { user };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'get_user', userId: id });
			}
		}
	);

	// create_user - Create a new user (FR8)
	server.registerTool(
		'create_user',
		{
			title: 'Create User',
			description: 'Create a new user with the specified attributes.',
			inputSchema: {
				username: z.string().describe('Username (required, must be unique)'),
				email: z.string().email().optional().describe('Email address'),
				firstName: z.string().optional().describe('First name'),
				lastName: z.string().optional().describe('Last name'),
				enabled: z.boolean().optional().describe('Whether user is enabled (default true)')
			},
			outputSchema: {
				user: UserSchema
			}
		},
		async ({ username, email, firstName, lastName, enabled }) => {
			try {
				const user = await userService.create({
					username,
					email,
					firstName,
					lastName,
					enabled
				});
				const output = { user };
				return {
					content: [
						{ type: 'text', text: `Created user "${username}" with ID: ${user.id}` },
						{ type: 'text', text: JSON.stringify(output, null, 2) }
					],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'create_user', username });
			}
		}
	);

	// update_user - Update user attributes (FR9)
	server.registerTool(
		'update_user',
		{
			title: 'Update User',
			description: 'Update attributes for an existing user. Only provided fields are updated.',
			inputSchema: {
				id: z.string().describe('User ID'),
				username: z.string().optional().describe('New username'),
				email: z.string().email().optional().describe('New email address'),
				firstName: z.string().optional().describe('New first name'),
				lastName: z.string().optional().describe('New last name'),
				enabled: z.boolean().optional().describe('Enable or disable user')
			},
			outputSchema: {
				user: UserSchema
			}
		},
		async ({ id, username, email, firstName, lastName, enabled }) => {
			try {
				const user = await userService.update(id, {
					username,
					email,
					firstName,
					lastName,
					enabled
				});
				const output = { user };
				return {
					content: [
						{ type: 'text', text: `Updated user ${id}` },
						{ type: 'text', text: JSON.stringify(output, null, 2) }
					],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'update_user', userId: id });
			}
		}
	);

	// delete_user - Delete a user (FR10)
	server.registerTool(
		'delete_user',
		{
			title: 'Delete User',
			description: 'Permanently delete a user. This action cannot be undone.',
			inputSchema: {
				id: z.string().describe('User ID to delete')
			},
			outputSchema: {
				success: z.boolean(),
				deletedUserId: z.string()
			}
		},
		async ({ id }) => {
			try {
				await userService.delete(id);
				const output = { success: true, deletedUserId: id };
				return {
					content: [{ type: 'text', text: `Successfully deleted user ${id}` }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'delete_user', userId: id });
			}
		}
	);

	// reset_user_password - Reset user's password (FR11)
	server.registerTool(
		'reset_user_password',
		{
			title: 'Reset User Password',
			description:
				'Set a new password for a user. Can be marked as temporary to force change on next login.',
			inputSchema: {
				id: z.string().describe('User ID'),
				password: z.string().min(1).describe('New password'),
				temporary: z
					.boolean()
					.optional()
					.describe('If true, user must change password on next login (default false)')
			},
			outputSchema: {
				success: z.boolean(),
				userId: z.string(),
				temporary: z.boolean()
			}
		},
		async ({ id, password, temporary }) => {
			try {
				await userService.resetPassword(id, password, temporary ?? false);
				const output = { success: true, userId: id, temporary: temporary ?? false };
				return {
					content: [
						{
							type: 'text',
							text: `Password reset for user ${id}${temporary ? ' (temporary - user must change on next login)' : ''}`
						}
					],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'reset_user_password', userId: id });
			}
		}
	);

	// get_user_credentials - List user's credentials (FR12)
	server.registerTool(
		'get_user_credentials',
		{
			title: 'Get User Credentials',
			description:
				'List all credentials (password, OTP devices, passkeys, etc.) configured for a user.',
			inputSchema: {
				id: z.string().describe('User ID')
			},
			outputSchema: {
				credentials: z.array(CredentialSchema),
				count: z.number()
			}
		},
		async ({ id }) => {
			try {
				const credentials = await userService.getCredentials(id);
				const output = { credentials, count: credentials.length };
				return {
					content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, { operation: 'get_user_credentials', userId: id });
			}
		}
	);

	// delete_user_credential - Remove a specific credential (FR13)
	server.registerTool(
		'delete_user_credential',
		{
			title: 'Delete User Credential',
			description:
				'Remove a specific credential from a user (e.g., a passkey or OTP device). This action cannot be undone.',
			inputSchema: {
				id: z.string().describe('User ID'),
				credentialId: z.string().describe('Credential ID to delete')
			},
			outputSchema: {
				success: z.boolean(),
				userId: z.string(),
				deletedCredentialId: z.string()
			}
		},
		async ({ id, credentialId }) => {
			try {
				await userService.deleteCredential(id, credentialId);
				const output = { success: true, userId: id, deletedCredentialId: credentialId };
				return {
					content: [{ type: 'text', text: `Deleted credential ${credentialId} from user ${id}` }],
					structuredContent: output
				};
			} catch (error) {
				return formatError(error, {
					operation: 'delete_user_credential',
					userId: id,
					credentialId
				});
			}
		}
	);
}
