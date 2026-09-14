import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type UserRepresentation from '@keycloak/keycloak-admin-client/lib/defs/userRepresentation';
import { ErrorCodes, IdentiKeyError } from '../../keycloak/errors';
import {
	BootstrapProvisionError,
	BootstrapProvisionCodes,
	provisionUser,
	findUserByProviderSub,
	createProvisionedUser
} from './provision';

function createMockClient(): {
	client: KcAdminClient;
	users: {
		find: Mock;
		create: Mock;
		update: Mock;
		findOne: Mock;
	};
} {
	const users = {
		find: vi.fn(),
		create: vi.fn(),
		update: vi.fn(),
		findOne: vi.fn()
	};
	return {
		client: { users } as unknown as KcAdminClient,
		users
	};
}

const APPLE_SUB = 'apple-user-001';
const GOOGLE_SUB = '12345678901234567890';

vi.mock('../../keycloak/client', () => ({
	getKeycloakClient: vi.fn()
}));

describe('provisionUser — new user', () => {
	it('creates Apple user with apple_sub attribute', async () => {
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([]);
		users.create.mockResolvedValue({ id: 'kc-user-1' });

		const result = await provisionUser('apple', {
			sub: APPLE_SUB,
			email: 'user@privaterelay.appleid.com',
			email_verified: true,
			is_private_email: true
		});

		expect(result.userId).toBe('kc-user-1');
		expect(result.isNewUser).toBe(true);
		expect(result.provider).toBe('apple');
		expect(result.email).toBe('user@privaterelay.appleid.com');
		expect(users.create).toHaveBeenCalledWith(
			expect.objectContaining({
				username: 'apple_apple-user-001',
				attributes: { apple_sub: [APPLE_SUB] },
				enabled: true
			})
		);
	});

	it('creates Google user with google_sub attribute and name', async () => {
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([]);
		users.create.mockResolvedValue({ id: 'kc-user-2' });

		const result = await provisionUser('google', {
			sub: GOOGLE_SUB,
			email: 'user@gmail.com',
			email_verified: true,
			name: 'Test User',
			picture: 'https://photo'
		});

		expect(result.userId).toBe('kc-user-2');
		expect(result.isNewUser).toBe(true);
		expect(result.provider).toBe('google');
		expect(users.create).toHaveBeenCalledWith(
			expect.objectContaining({
				username: 'google_12345678901234567890',
				firstName: 'Test User',
				attributes: { google_sub: [GOOGLE_SUB] }
			})
		);
	});

	it('returns isNewUser: true for new user', async () => {
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([]);
		users.create.mockResolvedValue({ id: 'new-id' });

		const result = await provisionUser('apple', { sub: APPLE_SUB });

		expect(result.isNewUser).toBe(true);
	});

	it('uses username format provider_sub(0,20)', async () => {
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([]);
		users.create.mockResolvedValue({ id: 'id' });

		await provisionUser('google', { sub: 'a'.repeat(30) });

		expect(users.create).toHaveBeenCalledWith(
			expect.objectContaining({
				username: 'google_aaaaaaaaaaaaaaaaaaaa'
			})
		);
	});
});

describe('provisionUser — existing user', () => {
	it('returns same user ID for Apple returning user', async () => {
		const existing: UserRepresentation = {
			id: 'existing-apple-id',
			username: 'apple_apple-user-001',
			attributes: { apple_sub: [APPLE_SUB] }
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		const result = await provisionUser('apple', { sub: APPLE_SUB });

		expect(result.userId).toBe('existing-apple-id');
		expect(result.isNewUser).toBe(false);
		expect(users.create).not.toHaveBeenCalled();
	});

	it('returns same user ID for Google returning user', async () => {
		const existing: UserRepresentation = {
			id: 'existing-google-id',
			username: 'google_12345678901234567890',
			attributes: { google_sub: [GOOGLE_SUB] }
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		const result = await provisionUser('google', { sub: GOOGLE_SUB, name: 'User' });

		expect(result.userId).toBe('existing-google-id');
		expect(result.isNewUser).toBe(false);
	});

	it('returns isNewUser: false for existing user', async () => {
		const existing: UserRepresentation = { id: 'id', attributes: { apple_sub: [APPLE_SUB] } };
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		const result = await provisionUser('apple', { sub: APPLE_SUB });

		expect(result.isNewUser).toBe(false);
	});
});

describe('provisionUser — profile update', () => {
	it('updates existing user when email is missing', async () => {
		const existing: UserRepresentation = {
			id: 'user-1',
			username: 'apple_apple-user-001',
			attributes: { apple_sub: [APPLE_SUB] }
			// no email
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		await provisionUser('apple', {
			sub: APPLE_SUB,
			email: 'new@example.com',
			email_verified: true
		});

		expect(users.update).toHaveBeenCalledWith(
			{ id: 'user-1' },
			expect.objectContaining({
				email: 'new@example.com',
				attributes: expect.objectContaining({ apple_sub: [APPLE_SUB] })
			})
		);
	});

	it('does not overwrite existing email with undefined (Apple subsequent auth)', async () => {
		const existing: UserRepresentation = {
			id: 'user-1',
			username: 'apple_apple-user-001',
			email: 'existing@example.com',
			attributes: { apple_sub: [APPLE_SUB] }
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		await provisionUser('apple', { sub: APPLE_SUB });
		// payload has no email (Apple subsequent auth) — no profile update needed, so update not called
		expect(users.update).not.toHaveBeenCalled();
	});

	it('update preserves existing attributes when merging', async () => {
		const existing: UserRepresentation = {
			id: 'user-1',
			username: 'apple_apple-user-001',
			attributes: { apple_sub: [APPLE_SUB] }
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		await provisionUser('apple', {
			sub: APPLE_SUB,
			email: 'fill@example.com',
			email_verified: true
		});

		const updatePayload = users.update.mock.calls[0][1];
		expect(updatePayload.attributes).toEqual(expect.objectContaining({ apple_sub: [APPLE_SUB] }));
	});
});

describe('provisionUser — Apple private relay', () => {
	it('stores private relay email as-is', async () => {
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([]);
		users.create.mockResolvedValue({ id: 'id' });

		await provisionUser('apple', {
			sub: APPLE_SUB,
			email: 'abc123@privaterelay.appleid.com',
			email_verified: true,
			is_private_email: true
		});

		expect(users.create).toHaveBeenCalledWith(
			expect.objectContaining({
				email: 'abc123@privaterelay.appleid.com'
			})
		);
	});

	it('missing email on subsequent auth does not clear existing email', async () => {
		const existing: UserRepresentation = {
			id: 'user-1',
			username: 'apple_apple-user-001',
			email: 'relay@privaterelay.appleid.com',
			attributes: { apple_sub: [APPLE_SUB] }
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		const result = await provisionUser('apple', { sub: APPLE_SUB });

		expect(result.userId).toBe('user-1');
		expect(result.email).toBe('relay@privaterelay.appleid.com');
		expect(users.update).not.toHaveBeenCalled();
	});
});

describe('provisionUser — errors', () => {
	it('throws IdentiKeyError on Keycloak connection failure', async () => {
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockRejectedValue(new IdentiKeyError('Connection failed', ErrorCodes.CONNECTION_FAILED));

		await expect(provisionUser('apple', { sub: APPLE_SUB })).rejects.toThrow(IdentiKeyError);
	});

	it('wraps connection-like errors in IdentiKeyError', async () => {
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		const err = Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
		getKeycloakClient.mockRejectedValue(err);

		await expect(provisionUser('apple', { sub: APPLE_SUB })).rejects.toMatchObject({
			name: 'IdentiKeyError',
			code: ErrorCodes.CONNECTION_FAILED
		});
	});

	it('throws BootstrapProvisionError when sub is missing', async () => {
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([]);

		await expect(
			provisionUser('apple', { sub: '' as unknown as string })
		).rejects.toMatchObject({
			constructor: BootstrapProvisionError,
			code: BootstrapProvisionCodes.MISSING_SUB,
			message: expect.stringContaining('sub')
		});
	});
});

describe('provisionUser — 409 conflict', () => {
	it('retries find after 409 and returns existing user ID', async () => {
		const existing: UserRepresentation = {
			id: 'race-winner-id',
			username: 'apple_apple-user-001',
			attributes: { apple_sub: [APPLE_SUB] }
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find
			.mockResolvedValueOnce([])
			.mockResolvedValueOnce([existing]);
		users.create.mockRejectedValueOnce(
			Object.assign(new Error('Conflict'), { response: { status: 409 } })
		);

		const result = await provisionUser('apple', {
			sub: APPLE_SUB,
			email: 'u@example.com',
			email_verified: true
		});

		expect(result.userId).toBe('race-winner-id');
		expect(users.find).toHaveBeenCalledTimes(2);
	});
});

describe('provisionUser — idempotency', () => {
	it('multiple provisions with same sub return same user ID', async () => {
		const existing: UserRepresentation = {
			id: 'same-user-id',
			username: 'google_12345678901234567890',
			attributes: { google_sub: [GOOGLE_SUB] }
		};
		const { client, users } = createMockClient();
		const getKeycloakClient = (await import('../../keycloak/client')).getKeycloakClient as Mock;
		getKeycloakClient.mockResolvedValue(client);
		users.find.mockResolvedValue([existing]);
		users.update.mockResolvedValue(undefined);

		const r1 = await provisionUser('google', { sub: GOOGLE_SUB, name: 'User' });
		const r2 = await provisionUser('google', { sub: GOOGLE_SUB, name: 'User' });

		expect(r1.userId).toBe('same-user-id');
		expect(r2.userId).toBe('same-user-id');
		expect(users.create).not.toHaveBeenCalled();
	});
});

describe('findUserByProviderSub', () => {
	it('returns null when no user found', async () => {
		const { client, users } = createMockClient();
		users.find.mockResolvedValue([]);

		const result = await findUserByProviderSub(client, 'apple', APPLE_SUB);

		expect(result).toBeNull();
		expect(users.find).toHaveBeenCalledWith({
			q: 'apple_sub:apple-user-001',
			exact: true
		});
	});

	it('returns first user when multiple (warning case)', async () => {
		const { client, users } = createMockClient();
		users.find.mockResolvedValue([
			{ id: 'first' },
			{ id: 'second' }
		]);

		const result = await findUserByProviderSub(client, 'google', GOOGLE_SUB);

		expect(result?.id).toBe('first');
		expect(users.find).toHaveBeenCalledWith({
			q: 'google_sub:12345678901234567890',
			exact: true
		});
	});
});

describe('createProvisionedUser', () => {
	it('throws BootstrapProvisionError on 409 when retry find returns empty', async () => {
		const { client, users } = createMockClient();
		users.find.mockResolvedValue([]);
		users.create.mockRejectedValue(
			Object.assign(new Error('Conflict'), { response: { status: 409 } })
		);

		await expect(
			createProvisionedUser(client, 'apple', { sub: APPLE_SUB })
		).rejects.toMatchObject({
			constructor: BootstrapProvisionError,
			code: BootstrapProvisionCodes.USER_CREATE_FAILED
		});
	});
});
