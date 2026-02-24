import { defineCommand } from 'citty';
import { getKeycloakClient } from '../../../lib/keycloak/client';
import { loadConfig } from '../../../lib/keycloak/config';
import { printSuccess, printError } from '../../utils/output';

export const enableCommand = defineCommand({
	meta: {
		name: 'enable',
		description: 'Enable event logging on the Keycloak realm'
	},
	args: {},
	async run() {
		try {
			const config = loadConfig();
			const client = await getKeycloakClient();

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const realm = await (client as any).realms.findOne({ realm: config.keycloakRealm });

			const alreadyEnabled = realm?.eventsEnabled && realm?.adminEventsEnabled;
			if (alreadyEnabled) {
				printSuccess('Event logging is already enabled on this realm.');
				return;
			}

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			await (client as any).realms.update(
				{ realm: config.keycloakRealm },
				{
					...realm,
					eventsEnabled: true,
					adminEventsEnabled: true,
					adminEventsDetailsEnabled: true,
					eventsExpiration: 604800 // 7 days
				}
			);

			printSuccess(
				`Event logging enabled on realm "${config.keycloakRealm}" (login + admin events, 7-day retention).`
			);
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
