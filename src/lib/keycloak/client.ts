import KcAdminClient from '@keycloak/keycloak-admin-client';
import type { Config } from './config';
import { loadConfig } from './config';

let client: KcAdminClient | null = null;
let initPromise: Promise<KcAdminClient> | null = null;

async function createClient(config?: Config): Promise<KcAdminClient> {
	const cfg = config ?? loadConfig();

	const kc = new KcAdminClient({
		baseUrl: cfg.keycloakUrl,
		realmName: cfg.keycloakRealm
	});

	await kc.auth({
		username: cfg.keycloakUsername,
		password: cfg.keycloakPassword,
		grantType: 'password',
		clientId: cfg.keycloakClientId
	});

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

/**
 * Placeholder hook for explicit connection validation.
 *
 * Story 1.5 will extend this to hit a lightweight Keycloak endpoint and
 * categorize failures; for now, successful authentication via
 * `getKeycloakClient()` is treated as minimal validation.
 */
export async function validateConnection(): Promise<void> {
	await getKeycloakClient();
}

// Test-only helper to reset the cached singleton between specs.
export function __resetClientForTests() {
	client = null;
	initPromise = null;
}
