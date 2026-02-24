import { defineCommand } from 'citty';
import { getClientService } from '../../../lib/keycloak/services';
import { printClientDetails, printJson, printError, printSuccess } from '../../utils/output';

export const updateCommand = defineCommand({
	meta: {
		name: 'update',
		description: 'Update a client configuration'
	},
	args: {
		clientId: {
			type: 'positional',
			description: 'The clientId to update',
			required: true
		},
		name: {
			type: 'string',
			description: 'Display name'
		},
		rootUrl: {
			type: 'string',
			description: 'Root URL'
		},
		redirectUris: {
			type: 'string',
			description: 'Comma-separated redirect URIs'
		},
		webOrigins: {
			type: 'string',
			description: 'Comma-separated web origins'
		},
		enabled: {
			type: 'string',
			description: 'Enable or disable (true/false)'
		},
		publicClient: {
			type: 'string',
			description: 'Public client (true/false)'
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const svc = await getClientService();

			const updated = await svc.update(args.clientId, {
				name: args.name,
				rootUrl: args.rootUrl,
				redirectUris: args.redirectUris?.split(',').map((s) => s.trim()),
				webOrigins: args.webOrigins?.split(',').map((s) => s.trim()),
				enabled: args.enabled !== undefined ? args.enabled.toLowerCase() === 'true' : undefined,
				publicClient:
					args.publicClient !== undefined
						? args.publicClient.toLowerCase() === 'true'
						: undefined
			});

			if (args.json) {
				printJson(updated);
			} else {
				printSuccess(`Updated client ${updated.clientId}`);
				printClientDetails(updated);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
