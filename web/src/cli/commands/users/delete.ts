/**
 * CLI: kc users delete <id>
 */

import { defineCommand } from 'citty';
import * as readline from 'readline';
import { getUserService } from '../../../lib/keycloak/services';
import { printError, printSuccess } from '../../utils/output';

/**
 * Prompt user for confirmation
 */
async function confirm(message: string): Promise<boolean> {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout
	});

	return new Promise((resolve) => {
		rl.question(`${message} [y/N] `, (answer) => {
			rl.close();
			resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
		});
	});
}

export const deleteCommand = defineCommand({
	meta: {
		name: 'delete',
		description: 'Permanently delete a user'
	},
	args: {
		id: {
			type: 'positional',
			description: 'User ID to delete',
			required: true
		},
		force: {
			type: 'boolean',
			description: 'Skip confirmation prompt'
		}
	},
	async run({ args }) {
		try {
			const userService = await getUserService();

			// Get user first to show what we're deleting
			const user = await userService.get(args.id);

			if (!args.force) {
				const confirmed = await confirm(
					`Delete user "${user.username}" (${user.id})? This cannot be undone.`
				);
				if (!confirmed) {
					// eslint-disable-next-line no-console
					console.log('Cancelled.');
					return;
				}
			}

			await userService.delete(args.id);
			printSuccess(`Deleted user "${user.username}" (${user.id})`);
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
