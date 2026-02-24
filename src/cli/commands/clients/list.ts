import { defineCommand } from 'citty';
import { getClientService } from '../../../lib/keycloak/services';
import { printClientsTable, printJson, printError } from '../../utils/output';

export const listCommand = defineCommand({
	meta: {
		name: 'list',
		description: 'List OIDC clients'
	},
	args: {
		search: {
			type: 'string',
			description: 'Filter by clientId'
		},
		max: {
			type: 'string',
			description: 'Maximum number of results (default 100)'
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const svc = await getClientService();
			const max = args.max ? parseInt(args.max, 10) : undefined;
			const clients = await svc.list({ search: args.search, max });

			if (args.json) {
				printJson(clients);
			} else {
				printClientsTable(clients);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
