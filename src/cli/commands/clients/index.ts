import { defineCommand } from 'citty';
import { listCommand } from './list';
import { getCommand } from './get';
import { updateCommand } from './update';
import { getSecretCommand } from './get-secret';

export const clientsCommand = defineCommand({
	meta: {
		name: 'clients',
		description: 'OIDC client management commands'
	},
	subCommands: {
		list: listCommand,
		get: getCommand,
		update: updateCommand,
		'get-secret': getSecretCommand
	}
});
