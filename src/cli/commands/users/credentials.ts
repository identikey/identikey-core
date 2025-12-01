/**
 * CLI: kc users credentials <id>
 */

import { defineCommand } from 'citty';
import * as readline from 'readline';
import { getUserService } from '../../../lib/keycloak/services';
import { printCredentialsTable, printJson, printError, printSuccess } from '../../utils/output';

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

export const credentialsCommand = defineCommand({
	meta: {
		name: 'credentials',
		description: 'List or delete user credentials (passkeys, OTP devices, etc.)'
	},
	args: {
		id: {
			type: 'positional',
			description: 'User ID',
			required: true
		},
		delete: {
			type: 'string',
			description: 'Credential ID to delete'
		},
		force: {
			type: 'boolean',
			description: 'Skip confirmation when deleting'
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const userService = await getUserService();

			if (args.delete) {
				// Delete credential mode
				const user = await userService.get(args.id);

				if (!args.force) {
					const confirmed = await confirm(
						`Delete credential "${args.delete}" from user "${user.username}"? This cannot be undone.`
					);
					if (!confirmed) {
						// eslint-disable-next-line no-console
						console.log('Cancelled.');
						return;
					}
				}

				await userService.deleteCredential(args.id, args.delete);
				printSuccess(`Deleted credential ${args.delete} from user "${user.username}"`);
			} else {
				// List credentials mode
				const credentials = await userService.getCredentials(args.id);

				if (args.json) {
					printJson(credentials);
				} else {
					const user = await userService.get(args.id);
					// eslint-disable-next-line no-console
					console.log(`Credentials for user "${user.username}":\n`);
					printCredentialsTable(credentials);
				}
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
