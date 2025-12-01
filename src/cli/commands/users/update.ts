/**
 * CLI: kc users update <id>
 */

import { defineCommand } from 'citty';
import { getUserService } from '../../../lib/keycloak/services';
import { printUserDetails, printJson, printError, printSuccess } from '../../utils/output';

export const updateCommand = defineCommand({
	meta: {
		name: 'update',
		description: 'Update attributes for an existing user'
	},
	args: {
		id: {
			type: 'positional',
			description: 'User ID',
			required: true
		},
		username: {
			type: 'string',
			description: 'New username'
		},
		email: {
			type: 'string',
			description: 'New email address'
		},
		firstName: {
			type: 'string',
			description: 'New first name'
		},
		lastName: {
			type: 'string',
			description: 'New last name'
		},
		enabled: {
			type: 'string',
			description: 'Enable or disable user (true/false)'
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const userService = await getUserService();

			// Parse enabled if provided
			let enabled: boolean | undefined;
			if (args.enabled !== undefined) {
				enabled = args.enabled.toLowerCase() === 'true';
			}

			const user = await userService.update(args.id, {
				username: args.username,
				email: args.email,
				firstName: args.firstName,
				lastName: args.lastName,
				enabled
			});

			if (args.json) {
				printJson(user);
			} else {
				printSuccess(`Updated user ${user.id}`);
				printUserDetails(user);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
