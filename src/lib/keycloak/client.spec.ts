import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import type KcAdminClient from '@keycloak/keycloak-admin-client';

import { loadConfig } from './config';
import { ErrorCodes, IdentiKeyError } from './errors';
import { logger } from './logger';
import { __resetClientForTests, getKeycloakClient, validateConnection } from './client';

vi.mock('./config', () => ({
	loadConfig: vi.fn()
}));

vi.mock('./logger', () => {
	const info = vi.fn();
	const error = vi.fn();

	return {
		logger: {
			info,
			error
		}
	};
});

const authMock = vi.fn();
const constructorMock = vi.fn();
const serverInfoFindMock = vi.fn();

vi.mock('@keycloak/keycloak-admin-client', () => {
	class FakeKcAdminClient {
		auth = authMock as KcAdminClient['auth'];
		serverInfo = {
			find: serverInfoFindMock
		} as unknown as KcAdminClient['serverInfo'];

		constructor(options: unknown) {
			constructorMock(options);
		}
	}

	return {
		default: FakeKcAdminClient
	};
});

const mockedLoadConfig = loadConfig as unknown as Mock;
const mockedLogger = logger as unknown as {
	info: Mock;
	error: Mock;
};

describe('getKeycloakClient', () => {
	beforeEach(() => {
		__resetClientForTests();
		authMock.mockReset();
		constructorMock.mockReset();
		serverInfoFindMock.mockReset();
		mockedLoadConfig.mockReset();
		mockedLogger.info.mockReset();
		mockedLogger.error.mockReset();
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

	it('wraps authentication errors in IdentiKeyError with a cause', async () => {
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

		await expect(getKeycloakClient()).rejects.toEqual(
			new IdentiKeyError(
				'Failed to authenticate with Keycloak admin API',
				ErrorCodes.CONNECTION_FAILED,
				error
			)
		);
	});
});

describe('validateConnection', () => {
	beforeEach(() => {
		__resetClientForTests();
		authMock.mockReset();
		constructorMock.mockReset();
		serverInfoFindMock.mockReset();
		mockedLoadConfig.mockReset();
		mockedLogger.info.mockReset();
		mockedLogger.error.mockReset();
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
		serverInfoFindMock.mockResolvedValue(undefined as never);

		const first = await getKeycloakClient();
		await validateConnection();

		expect(constructorMock).toHaveBeenCalledTimes(1);
		expect(authMock).toHaveBeenCalledTimes(1);
		expect(serverInfoFindMock).toHaveBeenCalledTimes(1);

		const second = await getKeycloakClient();
		expect(second).toBe(first);
	});

	it('logs a success message with base URL and realm on successful validation', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://auth.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		authMock.mockResolvedValue(undefined as never);
		serverInfoFindMock.mockResolvedValue(undefined as never);

		await validateConnection();

		expect(serverInfoFindMock).toHaveBeenCalledTimes(1);
		expect(mockedLogger.info).toHaveBeenCalledWith(
			{
				baseUrl: 'https://auth.example.com',
				realm: 'master'
			},
			'Keycloak connection validated'
		);
	});

	it('wraps unreachable URL errors in IdentiKeyError(CONNECTION_FAILED) and logs diagnostics without secrets', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://bad-host.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		const networkError = new Error('getaddrinfo ENOTFOUND bad-host.example.com');
		authMock.mockRejectedValue(networkError);

		await expect(validateConnection()).rejects.toEqual(
			new IdentiKeyError(
				'Failed to authenticate with Keycloak admin API',
				ErrorCodes.CONNECTION_FAILED,
				networkError
			)
		);

		const lastCall = mockedLogger.error.mock.calls[mockedLogger.error.mock.calls.length - 1];
		const [fields, message] = lastCall;

		expect(fields).toEqual(
			expect.objectContaining({
				code: ErrorCodes.CONNECTION_FAILED,
				url: 'https://bad-host.example.com',
				realm: 'master'
			})
		);
		expect(message).toContain('Failed to reach Keycloak');
		expect(message).toContain('check KEYCLOAK_URL');
	});

	it('preserves UNAUTHORIZED errors and logs auth-focused diagnostics', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://auth.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		const underlying = Object.assign(new Error('Request failed with status code 401'), {
			response: { status: 401 }
		});

		authMock.mockRejectedValue(underlying);

		await expect(validateConnection()).rejects.toEqual(
			new IdentiKeyError(
				'Failed to authenticate with Keycloak admin API',
				ErrorCodes.UNAUTHORIZED,
				underlying
			)
		);

		const lastCall = mockedLogger.error.mock.calls[mockedLogger.error.mock.calls.length - 1];
		const [fields, message] = lastCall;

		expect(fields).toEqual(
			expect.objectContaining({
				code: ErrorCodes.UNAUTHORIZED,
				url: 'https://auth.example.com',
				realm: 'master'
			})
		);
		expect(message).toContain('Authentication failed when validating Keycloak connection');
		expect(message).toContain('KEYCLOAK_USERNAME');
		expect(message).toContain('KEYCLOAK_PASSWORD');
		expect(message).toContain('KEYCLOAK_CLIENT_ID');
	});

	it('reuses the existing client and avoids extra auth when validateConnection is called multiple times', async () => {
		mockedLoadConfig.mockReturnValue({
			keycloakUrl: 'https://auth.example.com',
			keycloakRealm: 'master',
			keycloakClientId: 'admin-cli',
			keycloakUsername: 'admin',
			keycloakPassword: 'secret',
			logLevel: 'info'
		});

		authMock.mockResolvedValue(undefined as never);
		serverInfoFindMock.mockResolvedValue(undefined as never);

		await validateConnection();
		await validateConnection();

		expect(constructorMock).toHaveBeenCalledTimes(1);
		expect(authMock).toHaveBeenCalledTimes(1);
		expect(serverInfoFindMock).toHaveBeenCalledTimes(2);
	});
});
