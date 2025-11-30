import KcAdminClient from '@keycloak/keycloak-admin-client';
import type { Config } from './config';
import { loadConfig } from './config';
import { ErrorCodes, IdentiKeyError, type ErrorCode } from './errors';
import { logger } from './logger';

const CONNECTIVITY_ERROR_CODES = new Set([
	'ENOTFOUND',
	'ECONNREFUSED',
	'EAI_AGAIN',
	'ECONNRESET',
	'ETIMEDOUT',
	'EPIPE',
	'EPROTO'
]);

function classifyConnectionError(error: Error): ErrorCode {
	const maybeStatus = (error as { response?: { status?: number } }).response?.status;

	if (maybeStatus === 401 || maybeStatus === 403) {
		return ErrorCodes.UNAUTHORIZED;
	}

	const nodeErrorCode = (error as { code?: string }).code;

	if (nodeErrorCode && CONNECTIVITY_ERROR_CODES.has(nodeErrorCode)) {
		return ErrorCodes.CONNECTION_FAILED;
	}

	return ErrorCodes.CONNECTION_FAILED;
}

let client: KcAdminClient | null = null;
let initPromise: Promise<KcAdminClient> | null = null;

async function createClient(config?: Config): Promise<KcAdminClient> {
	const cfg = config ?? loadConfig();

	const kc = new KcAdminClient({
		baseUrl: cfg.keycloakUrl,
		realmName: cfg.keycloakRealm
	});

	try {
		await kc.auth({
			username: cfg.keycloakUsername,
			password: cfg.keycloakPassword,
			grantType: 'password',
			clientId: cfg.keycloakClientId
		});
	} catch (unknownError) {
		const error =
			unknownError instanceof Error
				? unknownError
				: new Error('Unknown error during Keycloak auth');

		const code = classifyConnectionError(error);

		logger.error(
			{
				code,
				error: {
					name: error.name,
					message: error.message
				}
			},
			'Failed to authenticate Keycloak admin client'
		);

		throw new IdentiKeyError('Failed to authenticate with Keycloak admin API', code, error);
	}

	return kc;
}

export async function getKeycloakClient(): Promise<KcAdminClient> {
	if (client) return client;

	if (!initPromise) {
		initPromise = createClient()
			.then((kc) => {
				client = kc;
				return kc;
			})
			.catch((err) => {
				initPromise = null;
				throw err;
			});
	}

	return initPromise;
}

export async function validateConnection(): Promise<void> {
	const cfg = loadConfig();

	try {
		const kc = await getKeycloakClient();

		// Lightweight, read-only probe to verify connectivity without extra auth overhead.
		// serverInfo is cheap and does not mutate server state.
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await (kc as any).serverInfo?.find();

		logger.info(
			{
				baseUrl: cfg.keycloakUrl,
				realm: cfg.keycloakRealm
			},
			'Keycloak connection validated'
		);
	} catch (unknownError) {
		const error =
			unknownError instanceof IdentiKeyError
				? unknownError
				: unknownError instanceof Error
					? unknownError
					: new Error('Unknown error during Keycloak connection validation');

		const code = error instanceof IdentiKeyError ? error.code : classifyConnectionError(error);

		const hint =
			code === ErrorCodes.UNAUTHORIZED
				? 'Authentication failed when validating Keycloak connection; check KEYCLOAK_USERNAME, KEYCLOAK_PASSWORD, and KEYCLOAK_CLIENT_ID.'
				: 'Failed to reach Keycloak; check KEYCLOAK_URL, network, DNS, and TLS configuration.';

		logger.error(
			{
				code,
				url: cfg.keycloakUrl,
				realm: cfg.keycloakRealm,
				error: {
					name: error.name,
					message: error.message
				}
			},
			hint
		);

		if (error instanceof IdentiKeyError) {
			throw error;
		}

		throw new IdentiKeyError(
			code === ErrorCodes.UNAUTHORIZED
				? 'Authentication failed when validating Keycloak connection'
				: 'Failed to validate Keycloak connection',
			code,
			error
		);
	}
}

// Test-only helper to reset the cached singleton between specs.
export function __resetClientForTests() {
	client = null;
	initPromise = null;
}
