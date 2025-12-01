/**
 * Service exports
 *
 * Provides factory functions for domain services that MCP and CLI can share.
 */

import { getKeycloakClient } from '../client';
import { UserService } from './users';

export { UserService } from './users';

/**
 * Get an authenticated UserService instance.
 * Uses the shared Keycloak client singleton.
 */
export async function getUserService(): Promise<UserService> {
	const client = await getKeycloakClient();
	return new UserService(client);
}
