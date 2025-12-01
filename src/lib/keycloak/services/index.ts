/**
 * Service exports
 *
 * Provides factory functions for domain services that MCP and CLI can share.
 */

import { getKeycloakClient } from '../client';
import { UserService } from './users';
import { AuthFlowService } from './auth-flows';

export { UserService } from './users';
export { AuthFlowService } from './auth-flows';

/**
 * Get an authenticated UserService instance.
 * Uses the shared Keycloak client singleton.
 */
export async function getUserService(): Promise<UserService> {
	const client = await getKeycloakClient();
	return new UserService(client);
}

/**
 * Get an authenticated AuthFlowService instance.
 * Uses the shared Keycloak client singleton.
 */
export async function getAuthFlowService(): Promise<AuthFlowService> {
	const client = await getKeycloakClient();
	return new AuthFlowService(client);
}
