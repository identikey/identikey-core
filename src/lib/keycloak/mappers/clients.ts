import type ClientRepresentation from '@keycloak/keycloak-admin-client/lib/defs/clientRepresentation';
import type { OidcClient } from '../types';

export function mapKeycloakClient(kc: ClientRepresentation): OidcClient {
	return {
		id: kc.id!,
		clientId: kc.clientId!,
		name: kc.name,
		description: kc.description,
		enabled: kc.enabled ?? false,
		protocol: kc.protocol ?? 'openid-connect',
		publicClient: kc.publicClient ?? false,
		rootUrl: kc.rootUrl,
		baseUrl: kc.baseUrl,
		adminUrl: kc.adminUrl,
		redirectUris: kc.redirectUris ?? [],
		webOrigins: kc.webOrigins ?? [],
		standardFlowEnabled: kc.standardFlowEnabled ?? false,
		implicitFlowEnabled: kc.implicitFlowEnabled ?? false,
		directAccessGrantsEnabled: kc.directAccessGrantsEnabled ?? false,
		serviceAccountsEnabled: kc.serviceAccountsEnabled ?? false
	};
}
