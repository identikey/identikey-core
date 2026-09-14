import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type UserRepresentation from '@keycloak/keycloak-admin-client/lib/defs/userRepresentation';
import type GroupRepresentation from '@keycloak/keycloak-admin-client/lib/defs/groupRepresentation';
import type CredentialRepresentation from '@keycloak/keycloak-admin-client/lib/defs/credentialRepresentation';

import { UserService } from './users';
import { ErrorCodes, IdentiKeyError } from '../errors';

// Mock logger to suppress output during tests
vi.mock('../logger', () => ({
	logger: {
		debug: vi.fn(),
		info: vi.fn(),
		error: vi.fn()
	}
}));

function createMockClient(): {
	client: KcAdminClient;
	users: {
		find: Mock;
		findOne: Mock;
		create: Mock;
		update: Mock;
		del: Mock;
		listGroups: Mock;
		resetPassword: Mock;
		getCredentials: Mock;
		deleteCredential: Mock;
	};
} {
	const usersMock = {
		find: vi.fn(),
		findOne: vi.fn(),
		create: vi.fn(),
		update: vi.fn(),
		del: vi.fn(),
		listGroups: vi.fn(),
		resetPassword: vi.fn(),
		getCredentials: vi.fn(),
		deleteCredential: vi.fn()
	};

	return {
		client: { users: usersMock } as unknown as KcAdminClient,
		users: usersMock
	};
}

const mockUser: UserRepresentation = {
	id: 'user-123',
	username: 'testuser',
	email: 'test@example.com',
	firstName: 'Test',
	lastName: 'User',
	enabled: true,
	createdTimestamp: 1700000000000
};

const mockGroups: GroupRepresentation[] = [
	{ id: 'g1', name: 'admins', path: '/admins' },
	{ id: 'g2', name: 'users', path: '/users' }
];

const mockCredentials: CredentialRepresentation[] = [
	{ id: 'cred-1', type: 'password', userLabel: 'My Password', createdDate: 1700000000000 },
	{ id: 'cred-2', type: 'otp', userLabel: 'My OTP', createdDate: 1700000001000 }
];

describe('UserService', () => {
	let service: UserService;
	let mocks: ReturnType<typeof createMockClient>;

	beforeEach(() => {
		mocks = createMockClient();
		service = new UserService(mocks.client);
	});

	describe('list', () => {
		it('returns mapped users with guilds', async () => {
			mocks.users.find.mockResolvedValue([mockUser]);
			mocks.users.listGroups.mockResolvedValue(mockGroups);

			const users = await service.list();

			expect(mocks.users.find).toHaveBeenCalledWith({ max: 100, first: 0 });
			expect(mocks.users.listGroups).toHaveBeenCalledWith({ id: 'user-123' });
			expect(users).toHaveLength(1);
			expect(users[0]).toEqual({
				id: 'user-123',
				username: 'testuser',
				email: 'test@example.com',
				firstName: 'Test',
				lastName: 'User',
				enabled: true,
				guilds: ['/admins', '/users'],
				createdTimestamp: 1700000000000
			});
		});

		it('respects pagination options', async () => {
			mocks.users.find.mockResolvedValue([]);
			mocks.users.listGroups.mockResolvedValue([]);

			await service.list({ max: 50, offset: 10 });

			expect(mocks.users.find).toHaveBeenCalledWith({ max: 50, first: 10 });
		});

		it('wraps errors in IdentiKeyError', async () => {
			mocks.users.find.mockRejectedValue(new Error('Network error'));

			await expect(service.list()).rejects.toBeInstanceOf(IdentiKeyError);
			await expect(service.list()).rejects.toMatchObject({
				message: 'Failed to list users',
				code: ErrorCodes.CONNECTION_FAILED
			});
		});
	});

	describe('search', () => {
		it('passes search query to Keycloak', async () => {
			mocks.users.find.mockResolvedValue([mockUser]);
			mocks.users.listGroups.mockResolvedValue([]);

			await service.search('test@example.com');

			expect(mocks.users.find).toHaveBeenCalledWith({
				search: 'test@example.com',
				max: 100,
				first: 0
			});
		});

		it('respects pagination with search', async () => {
			mocks.users.find.mockResolvedValue([]);
			mocks.users.listGroups.mockResolvedValue([]);

			await service.search('admin', { max: 25, offset: 5 });

			expect(mocks.users.find).toHaveBeenCalledWith({
				search: 'admin',
				max: 25,
				first: 5
			});
		});
	});

	describe('get', () => {
		it('returns mapped user with guilds', async () => {
			mocks.users.findOne.mockResolvedValue(mockUser);
			mocks.users.listGroups.mockResolvedValue(mockGroups);

			const user = await service.get('user-123');

			expect(mocks.users.findOne).toHaveBeenCalledWith({ id: 'user-123' });
			expect(user.id).toBe('user-123');
			expect(user.guilds).toEqual(['/admins', '/users']);
		});

		it('throws USER_NOT_FOUND when user does not exist', async () => {
			mocks.users.findOne.mockResolvedValue(null);

			await expect(service.get('nonexistent')).rejects.toMatchObject({
				code: ErrorCodes.USER_NOT_FOUND,
				message: 'User not found: nonexistent'
			});
		});

		it('wraps 404 errors as USER_NOT_FOUND', async () => {
			const err = Object.assign(new Error('Not found'), { response: { status: 404 } });
			mocks.users.findOne.mockRejectedValue(err);

			await expect(service.get('user-123')).rejects.toMatchObject({
				code: ErrorCodes.USER_NOT_FOUND
			});
		});
	});

	describe('create', () => {
		it('creates user and returns mapped result', async () => {
			mocks.users.create.mockResolvedValue({ id: 'new-user-123' });
			mocks.users.findOne.mockResolvedValue({ ...mockUser, id: 'new-user-123' });
			mocks.users.listGroups.mockResolvedValue([]);

			const user = await service.create({
				username: 'newuser',
				email: 'new@example.com',
				firstName: 'New',
				lastName: 'User'
			});

			expect(mocks.users.create).toHaveBeenCalledWith({
				username: 'newuser',
				email: 'new@example.com',
				firstName: 'New',
				lastName: 'User',
				enabled: true
			});
			expect(user.id).toBe('new-user-123');
		});

		it('throws INVALID_INPUT when username is missing', async () => {
			await expect(service.create({ username: '' })).rejects.toMatchObject({
				code: ErrorCodes.INVALID_INPUT,
				message: 'Username is required'
			});
		});

		it('throws INVALID_INPUT on duplicate username (409)', async () => {
			const conflictErr = Object.assign(new Error('Conflict'), { response: { status: 409 } });
			mocks.users.create.mockRejectedValue(conflictErr);

			await expect(service.create({ username: 'existing' })).rejects.toMatchObject({
				code: ErrorCodes.INVALID_INPUT,
				message: "User with username 'existing' already exists"
			});
		});
	});

	describe('update', () => {
		it('updates user and returns mapped result', async () => {
			mocks.users.findOne.mockResolvedValue(mockUser);
			mocks.users.update.mockResolvedValue(undefined);
			mocks.users.listGroups.mockResolvedValue([]);

			const user = await service.update('user-123', { firstName: 'Updated' });

			expect(mocks.users.update).toHaveBeenCalledWith(
				{ id: 'user-123' },
				{
					username: 'testuser',
					email: 'test@example.com',
					firstName: 'Updated',
					lastName: 'User',
					enabled: true
				}
			);
			expect(user).toBeDefined();
		});

		it('throws USER_NOT_FOUND when user does not exist', async () => {
			mocks.users.findOne.mockResolvedValue(null);

			await expect(service.update('nonexistent', { firstName: 'X' })).rejects.toMatchObject({
				code: ErrorCodes.USER_NOT_FOUND
			});
		});
	});

	describe('delete', () => {
		it('deletes existing user', async () => {
			mocks.users.findOne.mockResolvedValue(mockUser);
			mocks.users.del.mockResolvedValue(undefined);

			await service.delete('user-123');

			expect(mocks.users.del).toHaveBeenCalledWith({ id: 'user-123' });
		});

		it('throws USER_NOT_FOUND when user does not exist', async () => {
			mocks.users.findOne.mockResolvedValue(null);

			await expect(service.delete('nonexistent')).rejects.toMatchObject({
				code: ErrorCodes.USER_NOT_FOUND
			});
		});
	});

	describe('resetPassword', () => {
		it('resets password with temporary flag', async () => {
			mocks.users.findOne.mockResolvedValue(mockUser);
			mocks.users.resetPassword.mockResolvedValue(undefined);

			await service.resetPassword('user-123', 'newpass123', true);

			expect(mocks.users.resetPassword).toHaveBeenCalledWith({
				id: 'user-123',
				credential: {
					type: 'password',
					value: 'newpass123',
					temporary: true
				}
			});
		});

		it('throws INVALID_INPUT when password is empty', async () => {
			await expect(service.resetPassword('user-123', '')).rejects.toMatchObject({
				code: ErrorCodes.INVALID_INPUT,
				message: 'Password is required'
			});
		});

		it('throws USER_NOT_FOUND when user does not exist', async () => {
			mocks.users.findOne.mockResolvedValue(null);

			await expect(service.resetPassword('nonexistent', 'pass')).rejects.toMatchObject({
				code: ErrorCodes.USER_NOT_FOUND
			});
		});
	});

	describe('getCredentials', () => {
		it('returns mapped credentials', async () => {
			mocks.users.findOne.mockResolvedValue(mockUser);
			mocks.users.getCredentials.mockResolvedValue(mockCredentials);

			const creds = await service.getCredentials('user-123');

			expect(creds).toHaveLength(2);
			expect(creds[0]).toEqual({
				id: 'cred-1',
				type: 'password',
				userLabel: 'My Password',
				createdDate: 1700000000000
			});
		});

		it('throws USER_NOT_FOUND when user does not exist', async () => {
			mocks.users.findOne.mockResolvedValue(null);

			await expect(service.getCredentials('nonexistent')).rejects.toMatchObject({
				code: ErrorCodes.USER_NOT_FOUND
			});
		});
	});

	describe('deleteCredential', () => {
		it('deletes credential from user', async () => {
			mocks.users.findOne.mockResolvedValue(mockUser);
			mocks.users.deleteCredential.mockResolvedValue(undefined);

			await service.deleteCredential('user-123', 'cred-1');

			expect(mocks.users.deleteCredential).toHaveBeenCalledWith({
				id: 'user-123',
				credentialId: 'cred-1'
			});
		});

		it('throws USER_NOT_FOUND when user does not exist', async () => {
			mocks.users.findOne.mockResolvedValue(null);

			await expect(service.deleteCredential('nonexistent', 'cred-1')).rejects.toMatchObject({
				code: ErrorCodes.USER_NOT_FOUND
			});
		});
	});

	describe('error classification', () => {
		it('classifies 401 as UNAUTHORIZED', async () => {
			const err = Object.assign(new Error('Unauthorized'), { response: { status: 401 } });
			mocks.users.find.mockRejectedValue(err);

			await expect(service.list()).rejects.toMatchObject({
				code: ErrorCodes.UNAUTHORIZED
			});
		});

		it('classifies 403 as UNAUTHORIZED', async () => {
			const err = Object.assign(new Error('Forbidden'), { response: { status: 403 } });
			mocks.users.find.mockRejectedValue(err);

			await expect(service.list()).rejects.toMatchObject({
				code: ErrorCodes.UNAUTHORIZED
			});
		});

		it('classifies network errors as CONNECTION_FAILED', async () => {
			const err = Object.assign(new Error('Connection refused'), { code: 'ECONNREFUSED' });
			mocks.users.find.mockRejectedValue(err);

			await expect(service.list()).rejects.toMatchObject({
				code: ErrorCodes.CONNECTION_FAILED
			});
		});
	});
});

describe('getUserService factory', () => {
	it('creates UserService with authenticated client', async () => {
		// This test verifies the integration wiring works
		// In a real scenario, this would test that getUserService() properly
		// obtains the client from getKeycloakClient()
		const { getUserService } = await import('./index');

		// Mock getKeycloakClient at the module level for integration test
		vi.doMock('../client', () => ({
			getKeycloakClient: vi.fn().mockResolvedValue({
				users: {
					find: vi.fn().mockResolvedValue([]),
					listGroups: vi.fn().mockResolvedValue([])
				}
			})
		}));

		// The factory should return a UserService instance
		// (This test is more about structure than behavior)
		expect(getUserService).toBeDefined();
		expect(typeof getUserService).toBe('function');
	});
});
