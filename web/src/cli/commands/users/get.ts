/**
 * CLI: kc users get <id>
 */

import { defineCommand } from 'citty';
import { getUserService } from '../../../lib/keycloak/services';
import { printUserDetails, printJson, printError } from '../../utils/output';

export const getCommand = defineCommand({
	meta: {
		name: 'get',
		description: 'Get detailed information for a specific user'
	},
	args: {
		id: {
			type: 'positional',
			description: 'User ID',
			required: true
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const userService = await getUserService();
			const user = await userService.get(args.id);

			if (args.json) {
				printJson(user);
			} else {
				printUserDetails(user);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
