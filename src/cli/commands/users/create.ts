/**
 * CLI: kc users create
 */

import { defineCommand } from 'citty';
import { getUserService } from '../../../lib/keycloak/services';
import { printUserDetails, printJson, printError, printSuccess } from '../../utils/output';

export const createCommand = defineCommand({
	meta: {
		name: 'create',
		description: 'Create a new user'
	},
	args: {
		username: {
			type: 'string',
			description: 'Username (required, must be unique)',
			required: true
		},
		email: {
			type: 'string',
			description: 'Email address'
		},
		firstName: {
			type: 'string',
			description: 'First name'
		},
		lastName: {
			type: 'string',
			description: 'Last name'
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const userService = await getUserService();

			const user = await userService.create({
				username: args.username,
				email: args.email,
				firstName: args.firstName,
				lastName: args.lastName,
				enabled: true
			});

			if (args.json) {
				printJson(user);
			} else {
				printSuccess(`Created user "${user.username}" with ID: ${user.id}`);
				printUserDetails(user);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
