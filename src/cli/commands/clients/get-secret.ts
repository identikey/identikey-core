import { defineCommand } from 'citty';
import { getClientService } from '../../../lib/keycloak/services';
import { printJson, printError } from '../../utils/output';

export const getSecretCommand = defineCommand({
	meta: {
		name: 'get-secret',
		description: 'Get the client secret for a confidential client'
	},
	args: {
		clientId: {
			type: 'positional',
			description: 'The clientId',
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
			const secret = await svc.getSecret(args.clientId);

			if (args.json) {
				printJson({ clientId: args.clientId, secret });
			} else {
				// eslint-disable-next-line no-console
				console.log(secret ?? '(no secret — client may be public)');
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
