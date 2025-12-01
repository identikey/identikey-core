/**
 * CLI: kc auth-flows executions <alias>
 */

import { defineCommand } from 'citty';
import { getAuthFlowService } from '../../../lib/keycloak/services';
import { printExecutionsTable, printJson, printError } from '../../utils/output';

export const executionsCommand = defineCommand({
	meta: {
		name: 'executions',
		description: 'List executions (steps) within an authentication flow'
	},
	args: {
		alias: {
			type: 'positional',
			description: 'Flow alias to list executions for',
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
			const executions = await authFlowService.listExecutions(args.alias);

			if (args.json) {
				printJson({ flowAlias: args.alias, executions });
			} else {
				printExecutionsTable(args.alias, executions);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
