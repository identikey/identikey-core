import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { UserService } from '../../lib/keycloak/services/users';
import type { User, Credential } from '../../lib/keycloak/types';
import { ErrorCodes, IdentiKeyError } from '../../lib/keycloak/errors';
import { registerUserTools } from './users';

// Mock user data
const mockUser: User = {
	id: 'user-123',
	username: 'testuser',
	email: 'test@example.com',
	firstName: 'Test',
	lastName: 'User',
	enabled: true,
	guilds: ['/admins'],
	createdTimestamp: 1700000000000
};

const mockCredentials: Credential[] = [
	{ id: 'cred-1', type: 'password', userLabel: 'My Password', createdDate: 1700000000000 },
	{ id: 'cred-2', type: 'webauthn', userLabel: 'My Passkey', createdDate: 1700000001000 }
];

function createMockUserService(): {
	service: UserService;
	mocks: {
		list: Mock;
		search: Mock;
		get: Mock;
		create: Mock;
		update: Mock;
		delete: Mock;
		resetPassword: Mock;
		getCredentials: Mock;
		deleteCredential: Mock;
	};
} {
	const mocks = {
		list: vi.fn(),
		search: vi.fn(),
		get: vi.fn(),
		create: vi.fn(),
		update: vi.fn(),
		delete: vi.fn(),
		resetPassword: vi.fn(),
		getCredentials: vi.fn(),
		deleteCredential: vi.fn()
	};

	return {
		service: mocks as unknown as UserService,
		mocks
	};
}

function createMockServer(): {
	server: McpServer;
	registeredTools: Map<string, { config: unknown; handler: (input: unknown) => Promise<unknown> }>;
} {
	const registeredTools = new Map<
		string,
		{ config: unknown; handler: (input: unknown) => Promise<unknown> }
	>();

	const server = {
		registerTool: vi.fn(
			(name: string, config: unknown, handler: (input: unknown) => Promise<unknown>) => {
				registeredTools.set(name, { config, handler });
			}
		)
	} as unknown as McpServer;

	return { server, registeredTools };
}

describe('User MCP Tools', () => {
	let mockServer: ReturnType<typeof createMockServer>;
	let mockUserService: ReturnType<typeof createMockUserService>;

	beforeEach(() => {
		mockServer = createMockServer();
		mockUserService = createMockUserService();
		registerUserTools(mockServer.server, mockUserService.service);
	});

	describe('tool registration', () => {
		it('registers all 8 user tools', () => {
			expect(mockServer.registeredTools.size).toBe(8);
			expect(mockServer.registeredTools.has('list_users')).toBe(true);
			expect(mockServer.registeredTools.has('get_user')).toBe(true);
			expect(mockServer.registeredTools.has('create_user')).toBe(true);
			expect(mockServer.registeredTools.has('update_user')).toBe(true);
			expect(mockServer.registeredTools.has('delete_user')).toBe(true);
			expect(mockServer.registeredTools.has('reset_user_password')).toBe(true);
			expect(mockServer.registeredTools.has('get_user_credentials')).toBe(true);
			expect(mockServer.registeredTools.has('delete_user_credential')).toBe(true);
		});
	});

	describe('list_users', () => {
		it('calls UserService.list without search', async () => {
			mockUserService.mocks.list.mockResolvedValue([mockUser]);

			const tool = mockServer.registeredTools.get('list_users')!;
			const result = await tool.handler({});

			expect(mockUserService.mocks.list).toHaveBeenCalledWith({
				max: undefined,
				offset: undefined
			});
			expect(result).toHaveProperty('structuredContent');
			expect(
				(result as { structuredContent: { users: User[] } }).structuredContent.users
			).toHaveLength(1);
		});

		it('calls UserService.search with search query', async () => {
			mockUserService.mocks.search.mockResolvedValue([mockUser]);

			const tool = mockServer.registeredTools.get('list_users')!;
			const result = await tool.handler({ search: 'test', max: 50, offset: 10 });

			expect(mockUserService.mocks.search).toHaveBeenCalledWith('test', { max: 50, offset: 10 });
			expect(result).toHaveProperty('structuredContent');
		});

		it('returns error response on failure', async () => {
			mockUserService.mocks.list.mockRejectedValue(
				new IdentiKeyError('Connection failed', ErrorCodes.CONNECTION_FAILED)
			);

			const tool = mockServer.registeredTools.get('list_users')!;
			const result = await tool.handler({});

			expect(result).toHaveProperty('isError', true);
			expect((result as { content: Array<{ text: string }> }).content[0].text).toContain(
				'CONNECTION_FAILED'
			);
		});
	});

	describe('get_user', () => {
		it('returns user with structuredContent', async () => {
			mockUserService.mocks.get.mockResolvedValue(mockUser);

			const tool = mockServer.registeredTools.get('get_user')!;
			const result = await tool.handler({ id: 'user-123' });

			expect(mockUserService.mocks.get).toHaveBeenCalledWith('user-123');
			expect((result as { structuredContent: { user: User } }).structuredContent.user.id).toBe(
				'user-123'
			);
		});

		it('returns error with user ID context on USER_NOT_FOUND', async () => {
			mockUserService.mocks.get.mockRejectedValue(
				new IdentiKeyError('User not found', ErrorCodes.USER_NOT_FOUND)
			);

			const tool = mockServer.registeredTools.get('get_user')!;
			const result = await tool.handler({ id: 'nonexistent' });

			expect(result).toHaveProperty('isError', true);
			expect((result as { content: Array<{ text: string }> }).content[0].text).toContain(
				'USER_NOT_FOUND'
			);
			expect((result as { content: Array<{ text: string }> }).content[0].text).toContain(
				'nonexistent'
			);
		});
	});

	describe('create_user', () => {
		it('creates user and returns result', async () => {
			mockUserService.mocks.create.mockResolvedValue({ ...mockUser, id: 'new-user' });

			const tool = mockServer.registeredTools.get('create_user')!;
			const result = await tool.handler({
				username: 'newuser',
				email: 'new@example.com',
				firstName: 'New',
				lastName: 'User',
				enabled: true
			});

			expect(mockUserService.mocks.create).toHaveBeenCalledWith({
				username: 'newuser',
				email: 'new@example.com',
				firstName: 'New',
				lastName: 'User',
				enabled: true
			});
			expect((result as { structuredContent: { user: User } }).structuredContent.user.id).toBe(
				'new-user'
			);
		});

		it('returns error on duplicate username', async () => {
			mockUserService.mocks.create.mockRejectedValue(
				new IdentiKeyError("User with username 'existing' already exists", ErrorCodes.INVALID_INPUT)
			);

			const tool = mockServer.registeredTools.get('create_user')!;
			const result = await tool.handler({ username: 'existing' });

			expect(result).toHaveProperty('isError', true);
			expect((result as { content: Array<{ text: string }> }).content[0].text).toContain(
				'INVALID_INPUT'
			);
		});
	});

	describe('update_user', () => {
		it('updates user and returns result', async () => {
			mockUserService.mocks.update.mockResolvedValue({ ...mockUser, firstName: 'Updated' });

			const tool = mockServer.registeredTools.get('update_user')!;
			const result = await tool.handler({ id: 'user-123', firstName: 'Updated' });

			expect(mockUserService.mocks.update).toHaveBeenCalledWith('user-123', {
				username: undefined,
				email: undefined,
				firstName: 'Updated',
				lastName: undefined,
				enabled: undefined
			});
			expect(result).toHaveProperty('structuredContent');
		});
	});

	describe('delete_user', () => {
		it('deletes user and returns success', async () => {
			mockUserService.mocks.delete.mockResolvedValue(undefined);

			const tool = mockServer.registeredTools.get('delete_user')!;
			const result = await tool.handler({ id: 'user-123' });

			expect(mockUserService.mocks.delete).toHaveBeenCalledWith('user-123');
			expect(
				(result as { structuredContent: { success: boolean } }).structuredContent.success
			).toBe(true);
			expect(
				(result as { structuredContent: { deletedUserId: string } }).structuredContent.deletedUserId
			).toBe('user-123');
		});
	});

	describe('reset_user_password', () => {
		it('resets password with temporary flag', async () => {
			mockUserService.mocks.resetPassword.mockResolvedValue(undefined);

			const tool = mockServer.registeredTools.get('reset_user_password')!;
			const result = await tool.handler({ id: 'user-123', password: 'newpass', temporary: true });

			expect(mockUserService.mocks.resetPassword).toHaveBeenCalledWith('user-123', 'newpass', true);
			expect(
				(result as { structuredContent: { temporary: boolean } }).structuredContent.temporary
			).toBe(true);
		});

		it('defaults temporary to false', async () => {
			mockUserService.mocks.resetPassword.mockResolvedValue(undefined);

			const tool = mockServer.registeredTools.get('reset_user_password')!;
			await tool.handler({ id: 'user-123', password: 'newpass' });

			expect(mockUserService.mocks.resetPassword).toHaveBeenCalledWith(
				'user-123',
				'newpass',
				false
			);
		});
	});

	describe('get_user_credentials', () => {
		it('returns credentials with count', async () => {
			mockUserService.mocks.getCredentials.mockResolvedValue(mockCredentials);

			const tool = mockServer.registeredTools.get('get_user_credentials')!;
			const result = await tool.handler({ id: 'user-123' });

			expect(mockUserService.mocks.getCredentials).toHaveBeenCalledWith('user-123');
			expect(
				(result as { structuredContent: { credentials: Credential[]; count: number } })
					.structuredContent.count
			).toBe(2);
			expect(
				(result as { structuredContent: { credentials: Credential[] } }).structuredContent
					.credentials[0].type
			).toBe('password');
		});
	});

	describe('delete_user_credential', () => {
		it('deletes credential and returns success', async () => {
			mockUserService.mocks.deleteCredential.mockResolvedValue(undefined);

			const tool = mockServer.registeredTools.get('delete_user_credential')!;
			const result = await tool.handler({ id: 'user-123', credentialId: 'cred-1' });

			expect(mockUserService.mocks.deleteCredential).toHaveBeenCalledWith('user-123', 'cred-1');
			expect(
				(result as { structuredContent: { success: boolean } }).structuredContent.success
			).toBe(true);
			expect(
				(result as { structuredContent: { deletedCredentialId: string } }).structuredContent
					.deletedCredentialId
			).toBe('cred-1');
		});
	});

	describe('error formatting', () => {
		it('includes error code in response', async () => {
			mockUserService.mocks.get.mockRejectedValue(
				new IdentiKeyError('Unauthorized', ErrorCodes.UNAUTHORIZED)
			);

			const tool = mockServer.registeredTools.get('get_user')!;
			const result = await tool.handler({ id: 'user-123' });

			expect((result as { content: Array<{ text: string }> }).content[0].text).toContain(
				'UNAUTHORIZED'
			);
		});

		it('includes operation context in error', async () => {
			mockUserService.mocks.deleteCredential.mockRejectedValue(
				new IdentiKeyError('Failed', ErrorCodes.CONNECTION_FAILED)
			);

			const tool = mockServer.registeredTools.get('delete_user_credential')!;
			const result = await tool.handler({ id: 'user-123', credentialId: 'cred-1' });

			const errorText = (result as { content: Array<{ text: string }> }).content[0].text;
			expect(errorText).toContain('delete_user_credential');
			expect(errorText).toContain('user-123');
			expect(errorText).toContain('cred-1');
		});
	});
});
