/**
 * User mappers
 *
 * Maps Keycloak UserRepresentation to IdentiKey User domain type.
 */

import type UserRepresentation from '@keycloak/keycloak-admin-client/lib/defs/userRepresentation';
import type CredentialRepresentation from '@keycloak/keycloak-admin-client/lib/defs/credentialRepresentation';
import type GroupRepresentation from '@keycloak/keycloak-admin-client/lib/defs/groupRepresentation';
import type { User, Credential } from '../types';

/**
 * Map a Keycloak UserRepresentation to IdentiKey User.
 * Groups are mapped to guild paths.
 */
export function mapKeycloakUser(kcUser: UserRepresentation, groups?: GroupRepresentation[]): User {
	return {
		id: kcUser.id!,
		username: kcUser.username!,
		email: kcUser.email,
		firstName: kcUser.firstName,
		lastName: kcUser.lastName,
		enabled: kcUser.enabled ?? false,
		guilds: groups?.map((g) => g.path ?? g.name ?? '') ?? [],
		createdTimestamp: kcUser.createdTimestamp
	};
}

/**
 * Map a Keycloak CredentialRepresentation to IdentiKey Credential.
 */
export function mapKeycloakCredential(kcCred: CredentialRepresentation): Credential {
	return {
		id: kcCred.id!,
		type: kcCred.type!,
		userLabel: kcCred.userLabel,
		createdDate: kcCred.createdDate
	};
}
