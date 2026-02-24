import { getKeycloakClient } from '../keycloak/client';
import { loadConfig } from '../keycloak/config';
import { EventBus } from './bus';
import { KeycloakEventSource } from './keycloak-source';

export type { IdentiKeyEvent, EventFilter, EventProvider } from './types';
export { EventBus } from './bus';
export { KeycloakEventSource } from './keycloak-source';

let busInstance: EventBus | null = null;

export async function getEventBus(): Promise<EventBus> {
	if (busInstance) return busInstance;

	const client = await getKeycloakClient();
	const config = loadConfig();

	const bus = new EventBus();
	bus.addProvider(new KeycloakEventSource(client, config.keycloakRealm));

	busInstance = bus;
	return bus;
}
