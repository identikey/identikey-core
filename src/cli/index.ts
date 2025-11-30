import { runMain, defineCommand } from 'citty';
import { loadConfig } from '../lib/keycloak/config';
import { validateConnection } from '../lib/keycloak/client';

const main = defineCommand({
	meta: {
		name: 'kc',
		description: 'IdentiKey Admin CLI'
	},
	run: async () => {
		// Load configuration and fail fast on misconfiguration
		let config;
		try {
			config = loadConfig();
		} catch (error) {
			// eslint-disable-next-line no-console
			console.error('Failed to load Keycloak configuration:', (error as Error).message);
			process.exitCode = 1;
			return;
		}

		// Perform a connection check before doing any work
		try {
			await validateConnection();
		} catch (error) {
			// validateConnection already logs structured diagnostics via logger
			// Surface a concise message for CLI users and exit non-zero.
			const message = (error as Error).message || 'Keycloak connection validation failed';
			// eslint-disable-next-line no-console
			console.error(`Connection validation failed: ${message}`);
			process.exitCode = 1;
			return;
		}

		// Placeholder: actual command routing will be implemented in later stories.
		// eslint-disable-next-line no-console
		console.log(
			'Connection to Keycloak validated. CLI is ready. (Commands to be implemented in Epic 2+)'
		);
	}
});

runMain(main);
