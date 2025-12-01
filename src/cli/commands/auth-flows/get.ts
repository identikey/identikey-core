/**
 * CLI: kc auth-flows get <alias>
 */

import { defineCommand } from 'citty';
import { getAuthFlowService } from '../../../lib/keycloak/services';
import { printFlowDetails, printJson, printError } from '../../utils/output';

export const getCommand = defineCommand({
	meta: {
		name: 'get',
		description: 'Get details for a specific authentication flow'
	},
	args: {
		alias: {
			type: 'positional',
			description: 'Flow alias (e.g., "browser", "direct grant")',
			required: true
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const authFlowService = await getAuthFlowService();
			const flow = await authFlowService.get(args.alias);

			if (args.json) {
				printJson(flow);
			} else {
				printFlowDetails(flow);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
