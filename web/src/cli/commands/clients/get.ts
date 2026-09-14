import { defineCommand } from 'citty';
import { getClientService } from '../../../lib/keycloak/services';
import { printClientDetails, printJson, printError } from '../../utils/output';

export const getCommand = defineCommand({
	meta: {
		name: 'get',
		description: 'Get detailed information for a client by clientId'
	},
	args: {
		clientId: {
			type: 'positional',
			description: 'The clientId (e.g. huly-provisions)',
			required: true
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const svc = await getClientService();
			const client = await svc.getByClientId(args.clientId);

			if (args.json) {
				printJson(client);
			} else {
				printClientDetails(client);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
