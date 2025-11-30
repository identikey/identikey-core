import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import type KcAdminClient from '@keycloak/keycloak-admin-client';

import { loadConfig } from './config';
import { __resetClientForTests, getKeycloakClient, validateConnection } from './client';

vi.mock('./config', () => ({
	loadConfig: vi.fn()
}));

const authMock = vi.fn();
const constructorMock = vi.fn();

vi.mock('@keycloak/keycloak-admin-client', () => {
	class FakeKcAdminClient {
		auth = authMock as KcAdminClient['auth'];

		constructor(options: unknown) {
			constructorMock(options);
		}
	}

	return {
		default: FakeKcAdminClient
	};
});

const mockedLoadConfig = loadConfig as unknown as Mock;

describe('getKeycloakClient', () => {
	beforeEach(() => {
		__resetClientForTests();
		authMock.mockReset();
		constructorMock.mockReset();
		mockedLoadConfig.mockReset();
	});

	it('constructs and authenticates a Keycloak client using configuration', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://auth.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		authMock.mockResolvedValue(undefined as never);

		const client = await getKeycloakClient();

		expect(constructorMock).toHaveBeenCalledTimes(1);
		expect(constructorMock).toHaveBeenCalledWith({
			baseUrl: 'https://auth.example.com',
			realmName: 'master'
		});

		expect(authMock).toHaveBeenCalledTimes(1);
		expect(authMock).toHaveBeenCalledWith({
			username: 'admin',
			password: 'secret',
			grantType: 'password',
			clientId: 'admin-cli'
		});

		// Basic sanity: the returned client is the instance created by the constructor mock.
		expect(client).toBeDefined();
	});

	it('returns a singleton client instance across multiple calls', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://auth.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		authMock.mockResolvedValue(undefined as never);

		const first = await getKeycloakClient();
		const second = await getKeycloakClient();

		expect(constructorMock).toHaveBeenCalledTimes(1);
		expect(authMock).toHaveBeenCalledTimes(1);
		expect(second).toBe(first);
	});

	it('propagates authentication errors without swallowing them', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://auth.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		const error = new Error('auth failed');
		authMock.mockRejectedValue(error);

		await expect(getKeycloakClient()).rejects.toBe(error);
	});
});

describe('validateConnection', () => {
	beforeEach(() => {
		__resetClientForTests();
		authMock.mockReset();
		constructorMock.mockReset();
		mockedLoadConfig.mockReset();
	});

	it('reuses the same singleton client when validating connection', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://auth.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		authMock.mockResolvedValue(undefined as never);

		const first = await getKeycloakClient();
		await validateConnection();

		expect(constructorMock).toHaveBeenCalledTimes(1);
		expect(authMock).toHaveBeenCalledTimes(1);

		const second = await getKeycloakClient();
		expect(second).toBe(first);
	});
});
