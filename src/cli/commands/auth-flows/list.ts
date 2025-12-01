/**
 * CLI: kc auth-flows list
 */

import { defineCommand } from 'citty';
import { getAuthFlowService } from '../../../lib/keycloak/services';
import { printFlowsTable, printJson, printError } from '../../utils/output';

export const listCommand = defineCommand({
	meta: {
		name: 'list',
		description: 'List all authentication flows'
	},
	args: {
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const authFlowService = await getAuthFlowService();
			const flows = await authFlowService.list();

			if (args.json) {
				printJson(flows);
			} else {
				printFlowsTable(flows);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
