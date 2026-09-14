/**
 * CLI: kc auth-flows copy <source> <new-alias>
 */

import { defineCommand } from 'citty';
import { getAuthFlowService } from '../../../lib/keycloak/services';
import { printFlowDetails, printJson, printError, printSuccess } from '../../utils/output';

export const copyCommand = defineCommand({
	meta: {
		name: 'copy',
		description: 'Create a copy of an existing authentication flow'
	},
	args: {
		source: {
			type: 'positional',
			description: 'Alias of the flow to copy',
			required: true
		},
		newAlias: {
			type: 'positional',
			description: 'Alias for the new flow',
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
			const newFlow = await authFlowService.copy(args.source, args.newAlias);

			if (args.json) {
				printJson({ copiedFrom: args.source, flow: newFlow });
			} else {
				printSuccess(`Created flow "${args.newAlias}" as copy of "${args.source}"`);
				printFlowDetails(newFlow);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
