/**
 * Tests for CLI user commands
 *
 * Tests argument parsing, output formatting, and error handling.
 * Mocks UserService to test CLI command logic in isolation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { User, Credential } from '../../../lib/keycloak/types';
import { IdentiKeyError, ErrorCodes } from '../../../lib/keycloak/errors';

// Mock the getUserService module
vi.mock('../../../lib/keycloak/services', () => ({
	getUserService: vi.fn()
}));

// Mock readline for confirmation prompts
vi.mock('readline', () => ({
	createInterface: vi.fn(() => ({
		question: vi.fn((_, callback) => callback('y')),
		close: vi.fn()
	}))
}));

import { getUserService } from '../../../lib/keycloak/services';

// Sample test data
const mockUser: User = {
	id: 'user-123',
	username: 'testuser',
	email: 'test@example.com',
	firstName: 'Test',
	lastName: 'User',
	enabled: true,
	guilds: ['guild-1'],
	createdTimestamp: Date.now()
};

const mockUsers: User[] = [
	mockUser,
	{
		id: 'user-456',
		username: 'anotheruser',
		email: 'another@example.com',
		enabled: false,
		guilds: []
	}
];

const mockCredential: Credential = {
	id: 'cred-123',
	type: 'password',
	userLabel: 'My Password',
	createdDate: Date.now()
};

describe('CLI User Commands - Output Utilities', () => {
	let consoleSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
	});

	afterEach(() => {
		consoleSpy.mockRestore();
		errorSpy.mockRestore();
		vi.clearAllMocks();
	});

	describe('printJson', () => {
		it('should output valid JSON', async () => {
			const { printJson } = await import('../../utils/output');
			printJson(mockUser);

			expect(consoleSpy).toHaveBeenCalledTimes(1);
			const output = consoleSpy.mock.calls[0][0];
			const parsed = JSON.parse(output);

			expect(parsed.id).toBe('user-123');
			expect(parsed.username).toBe('testuser');
		});

		it('should pretty-print with 2-space indentation', async () => {
			const { printJson } = await import('../../utils/output');
			printJson({ a: 1 });

			const output = consoleSpy.mock.calls[0][0];
			expect(output).toBe('{\n  "a": 1\n}');
		});
	});

	describe('printUsersTable', () => {
		it('should print table with expected columns', async () => {
			const { printUsersTable } = await import('../../utils/output');
			printUsersTable(mockUsers);

			const calls = consoleSpy.mock.calls.map((c) => c[0]);
			const header = calls[0];

			expect(header).toContain('ID');
			expect(header).toContain('USERNAME');
			expect(header).toContain('EMAIL');
			expect(header).toContain('ENABLED');
		});

		it('should print user data rows', async () => {
			const { printUsersTable } = await import('../../utils/output');
			printUsersTable(mockUsers);

			const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');

			expect(allOutput).toContain('user-123');
			expect(allOutput).toContain('testuser');
			expect(allOutput).toContain('test@example.com');
			expect(allOutput).toContain('yes');

			expect(allOutput).toContain('user-456');
			expect(allOutput).toContain('anotheruser');
			expect(allOutput).toContain('no');
		});

		it('should show count at the end', async () => {
			const { printUsersTable } = await import('../../utils/output');
			printUsersTable(mockUsers);

			const lastCall = consoleSpy.mock.calls[consoleSpy.mock.calls.length - 1][0];
			expect(lastCall).toContain('2 user(s) found');
		});

		it('should handle empty list', async () => {
			const { printUsersTable } = await import('../../utils/output');
			printUsersTable([]);

			expect(consoleSpy).toHaveBeenCalledWith('No users found.');
		});
	});

	describe('printUserDetails', () => {
		it('should print all user fields', async () => {
			const { printUserDetails } = await import('../../utils/output');
			printUserDetails(mockUser);

			const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');

			expect(allOutput).toContain('testuser');
			expect(allOutput).toContain('user-123');
			expect(allOutput).toContain('test@example.com');
			expect(allOutput).toContain('Test');
			expect(allOutput).toContain('User');
			expect(allOutput).toContain('yes');
			expect(allOutput).toContain('guild-1');
		});

		it('should show "(not set)" for missing optional fields', async () => {
			const { printUserDetails } = await import('../../utils/output');
			printUserDetails({
				id: 'x',
				username: 'minimal',
				enabled: true,
				guilds: []
			});

			const allOutput = consoleSpy.mock.calls.map((c) => c[0]).join('\n');
			expect(allOutput).toContain('(not set)');
		});
	});

	describe('printCredentialsTable', () => {
		it('should print credentials table with expected columns', async () => {
			const { printCredentialsTable } = await import('../../utils/output');
			printCredentialsTable([mockCredential]);

			const calls = consoleSpy.mock.calls.map((c) => c[0]);
			const header = calls[0];

			expect(header).toContain('ID');
			expect(header).toContain('TYPE');
			expect(header).toContain('LABEL');
			expect(header).toContain('CREATED');
		});

		it('should handle empty credentials list', async () => {
			const { printCredentialsTable } = await import('../../utils/output');
			printCredentialsTable([]);

			expect(consoleSpy).toHaveBeenCalledWith('No credentials found.');
		});
	});

	describe('printError', () => {
		it('should format IdentiKeyError with code', async () => {
			const { printError } = await import('../../utils/output');
			const error = new IdentiKeyError('User not found', ErrorCodes.USER_NOT_FOUND);
			printError(error);

			expect(errorSpy).toHaveBeenCalledWith('Error [USER_NOT_FOUND]: User not found');
		});

		it('should handle regular Error', async () => {
			const { printError } = await import('../../utils/output');
			printError(new Error('Something went wrong'));

			expect(errorSpy).toHaveBeenCalledWith('Error: Something went wrong');
		});

		it('should handle non-Error values', async () => {
			const { printError } = await import('../../utils/output');
			printError('string error');

			expect(errorSpy).toHaveBeenCalledWith('Error: string error');
		});
	});
});

describe('CLI User Commands - Command Integration', () => {
	let mockUserService: {
		list: ReturnType<typeof vi.fn>;
		search: ReturnType<typeof vi.fn>;
		get: ReturnType<typeof vi.fn>;
		create: ReturnType<typeof vi.fn>;
		update: ReturnType<typeof vi.fn>;
		delete: ReturnType<typeof vi.fn>;
		resetPassword: ReturnType<typeof vi.fn>;
		getCredentials: ReturnType<typeof vi.fn>;
		deleteCredential: ReturnType<typeof vi.fn>;
	};

	let consoleSpy: ReturnType<typeof vi.spyOn>;
	let errorSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		mockUserService = {
			list: vi.fn().mockResolvedValue(mockUsers),
			search: vi.fn().mockResolvedValue([mockUser]),
			get: vi.fn().mockResolvedValue(mockUser),
			create: vi.fn().mockResolvedValue(mockUser),
			update: vi.fn().mockResolvedValue(mockUser),
			delete: vi.fn().mockResolvedValue(undefined),
			resetPassword: vi.fn().mockResolvedValue(undefined),
			getCredentials: vi.fn().mockResolvedValue([mockCredential]),
			deleteCredential: vi.fn().mockResolvedValue(undefined)
		};

		vi.mocked(getUserService).mockResolvedValue(mockUserService as never);
		consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		process.exitCode = undefined;
	});

	afterEach(() => {
		consoleSpy.mockRestore();
		errorSpy.mockRestore();
		vi.clearAllMocks();
	});

	describe('list command', () => {
		it('should call UserService.list without search', async () => {
			const { listCommand } = await import('./list');
			await listCommand.run!({ args: {}, rawArgs: [], cmd: listCommand });

			expect(mockUserService.list).toHaveBeenCalledWith({ max: undefined });
			expect(mockUserService.search).not.toHaveBeenCalled();
		});

		it('should call UserService.search with search parameter', async () => {
			const { listCommand } = await import('./list');
			await listCommand.run!({ args: { search: 'test' }, rawArgs: [], cmd: listCommand });

			expect(mockUserService.search).toHaveBeenCalledWith('test', { max: undefined });
			expect(mockUserService.list).not.toHaveBeenCalled();
		});

		it('should output JSON when --json flag is set', async () => {
			const { listCommand } = await import('./list');
			await listCommand.run!({ args: { json: true }, rawArgs: [], cmd: listCommand });

			const output = consoleSpy.mock.calls[0][0];
			const parsed = JSON.parse(output);

			expect(Array.isArray(parsed)).toBe(true);
			expect(parsed[0].id).toBe('user-123');
		});

		it('should respect max parameter', async () => {
			const { listCommand } = await import('./list');
			await listCommand.run!({ args: { max: '10' }, rawArgs: [], cmd: listCommand });

			expect(mockUserService.list).toHaveBeenCalledWith({ max: 10 });
		});
	});

	describe('get command', () => {
		it('should call UserService.get with user ID', async () => {
			const { getCommand } = await import('./get');
			await getCommand.run!({ args: { id: 'user-123' }, rawArgs: [], cmd: getCommand });

			expect(mockUserService.get).toHaveBeenCalledWith('user-123');
		});

		it('should output JSON when --json flag is set', async () => {
			const { getCommand } = await import('./get');
			await getCommand.run!({ args: { id: 'user-123', json: true }, rawArgs: [], cmd: getCommand });

			const output = consoleSpy.mock.calls[0][0];
			const parsed = JSON.parse(output);

			expect(parsed.id).toBe('user-123');
		});

		it('should handle USER_NOT_FOUND error', async () => {
			mockUserService.get.mockRejectedValueOnce(
				new IdentiKeyError('User not found', ErrorCodes.USER_NOT_FOUND)
			);

			const { getCommand } = await import('./get');
			await getCommand.run!({
				args: { id: 'nonexistent' },
				rawArgs: [],
				cmd: getCommand
			});

			expect(errorSpy).toHaveBeenCalledWith('Error [USER_NOT_FOUND]: User not found');
			expect(process.exitCode).toBe(1);
		});
	});

	describe('create command', () => {
		it('should call UserService.create with correct parameters', async () => {
			const { createCommand } = await import('./create');
			await createCommand.run!({
				args: {
					username: 'newuser',
					email: 'new@example.com',
					firstName: 'New',
					lastName: 'User'
				},
				rawArgs: [],
				cmd: createCommand
			});

			expect(mockUserService.create).toHaveBeenCalledWith({
				username: 'newuser',
				email: 'new@example.com',
				firstName: 'New',
				lastName: 'User',
				enabled: true
			});
		});
	});

	describe('update command', () => {
		it('should call UserService.update with provided fields', async () => {
			const { updateCommand } = await import('./update');
			await updateCommand.run!({
				args: {
					id: 'user-123',
					email: 'updated@example.com',
					enabled: 'false'
				},
				rawArgs: [],
				cmd: updateCommand
			});

			expect(mockUserService.update).toHaveBeenCalledWith('user-123', {
				username: undefined,
				email: 'updated@example.com',
				firstName: undefined,
				lastName: undefined,
				enabled: false
			});
		});

		it('should parse enabled=true correctly', async () => {
			const { updateCommand } = await import('./update');
			await updateCommand.run!({
				args: { id: 'user-123', enabled: 'true' },
				rawArgs: [],
				cmd: updateCommand
			});

			expect(mockUserService.update).toHaveBeenCalledWith(
				'user-123',
				expect.objectContaining({ enabled: true })
			);
		});
	});

	describe('delete command', () => {
		it('should call UserService.delete', async () => {
			const { deleteCommand } = await import('./delete');
			await deleteCommand.run!({
				args: { id: 'user-123', force: true },
				rawArgs: [],
				cmd: deleteCommand
			});

			expect(mockUserService.delete).toHaveBeenCalledWith('user-123');
		});
	});

	describe('credentials command', () => {
		it('should call UserService.getCredentials', async () => {
			const { credentialsCommand } = await import('./credentials');
			await credentialsCommand.run!({
				args: { id: 'user-123' },
				rawArgs: [],
				cmd: credentialsCommand
			});

			expect(mockUserService.getCredentials).toHaveBeenCalledWith('user-123');
		});

		it('should call UserService.deleteCredential when --delete is provided', async () => {
			const { credentialsCommand } = await import('./credentials');
			await credentialsCommand.run!({
				args: { id: 'user-123', delete: 'cred-456', force: true },
				rawArgs: [],
				cmd: credentialsCommand
			});

			expect(mockUserService.deleteCredential).toHaveBeenCalledWith('user-123', 'cred-456');
		});

		it('should output JSON when --json flag is set', async () => {
			const { credentialsCommand } = await import('./credentials');
			await credentialsCommand.run!({
				args: { id: 'user-123', json: true },
				rawArgs: [],
				cmd: credentialsCommand
			});

			const output = consoleSpy.mock.calls[0][0];
			const parsed = JSON.parse(output);

			expect(Array.isArray(parsed)).toBe(true);
			expect(parsed[0].id).toBe('cred-123');
		});
	});
});
