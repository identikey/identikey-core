/**
 * CLI: kc users list
 */

import { defineCommand } from 'citty';
import { getUserService } from '../../../lib/keycloak/services';
import { printUsersTable, printJson, printError } from '../../utils/output';

export const listCommand = defineCommand({
	meta: {
		name: 'list',
		description: 'List users with optional search filter'
	},
	args: {
		search: {
			type: 'string',
			description: 'Search query to filter users by username, email, first name, or last name'
		},
		max: {
			type: 'string',
			description: 'Maximum number of results (default 100)'
		},
		offset: {
			type: 'string',
			description: 'Offset for pagination (default 0)'
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const userService = await getUserService();

			const max = args.max ? parseInt(args.max, 10) : undefined;
			const offset = args.offset ? parseInt(args.offset, 10) : undefined;
			const users = args.search
				? await userService.search(args.search, { max, offset })
				: await userService.list({ max, offset });

			if (args.json) {
				printJson(users);
			} else {
				printUsersTable(users);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
