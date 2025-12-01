/**
 * CLI: kc users
 *
 * User management subcommands
 */

import { defineCommand } from 'citty';
import { listCommand } from './list';
import { getCommand } from './get';
import { createCommand } from './create';
import { updateCommand } from './update';
import { deleteCommand } from './delete';
import { resetPasswordCommand } from './reset-password';
import { credentialsCommand } from './credentials';

export const usersCommand = defineCommand({
	meta: {
		name: 'users',
		description: 'User management commands'
	},
	subCommands: {
		list: listCommand,
		get: getCommand,
		create: createCommand,
		update: updateCommand,
		delete: deleteCommand,
		'reset-password': resetPasswordCommand,
		credentials: credentialsCommand
	}
});
