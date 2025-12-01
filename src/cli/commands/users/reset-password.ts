/**
 * CLI: kc users reset-password <id>
 */

import { defineCommand } from 'citty';
import * as readline from 'readline';
import { getUserService } from '../../../lib/keycloak/services';
import { printError, printSuccess } from '../../utils/output';

/**
 * Prompt for password input (attempts to hide input on supported terminals)
 */
async function promptPassword(prompt: string): Promise<string> {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout
	});

	// Try to hide input if terminal supports it
	const stdin = process.stdin;
	const wasRaw = stdin.isRaw;

	return new Promise((resolve, reject) => {
		// Write prompt manually to avoid the question echoing
		process.stdout.write(prompt);

		let password = '';

		if (stdin.isTTY) {
			stdin.setRawMode(true);
			stdin.resume();
			stdin.setEncoding('utf8');

			const onData = (char: string) => {
				if (char === '\n' || char === '\r') {
					stdin.setRawMode(wasRaw ?? false);
					stdin.removeListener('data', onData);
					rl.close();
					process.stdout.write('\n');
					resolve(password);
				} else if (char === '\u0003') {
					// Ctrl+C
					stdin.setRawMode(wasRaw ?? false);
					stdin.removeListener('data', onData);
					rl.close();
					reject(new Error('Cancelled'));
				} else if (char === '\u007F' || char === '\b') {
					// Backspace
					if (password.length > 0) {
						password = password.slice(0, -1);
					}
				} else {
					password += char;
				}
			};

			stdin.on('data', onData);
		} else {
			// Fallback for non-TTY (pipes, etc)
			rl.question('', (answer) => {
				rl.close();
				resolve(answer);
			});
		}
	});
}

export const resetPasswordCommand = defineCommand({
	meta: {
		name: 'reset-password',
		description: 'Set a new password for a user'
	},
	args: {
		id: {
			type: 'positional',
			description: 'User ID',
			required: true
		},
		temporary: {
			type: 'boolean',
			description: 'User must change password on next login'
		}
	},
	async run({ args }) {
		try {
			const userService = await getUserService();

			// Verify user exists first
			const user = await userService.get(args.id);

			// Prompt for password
			const password = await promptPassword(`New password for "${user.username}": `);

			if (!password) {
				// eslint-disable-next-line no-console
				console.error('Password cannot be empty.');
				process.exitCode = 1;
				return;
			}

			// Confirm password
			const confirmPassword = await promptPassword('Confirm password: ');

			if (password !== confirmPassword) {
				// eslint-disable-next-line no-console
				console.error('Passwords do not match.');
				process.exitCode = 1;
				return;
			}

			await userService.resetPassword(args.id, password, args.temporary ?? false);

			const suffix = args.temporary ? ' (temporary - must change on next login)' : '';
			printSuccess(`Password reset for "${user.username}"${suffix}`);
		} catch (error) {
			if ((error as Error).message === 'Cancelled') {
				// eslint-disable-next-line no-console
				console.log('\nCancelled.');
				return;
			}
			printError(error);
			process.exitCode = 1;
		}
	}
});
