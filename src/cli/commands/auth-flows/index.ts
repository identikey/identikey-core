/**
 * CLI: kc auth-flows
 *
 * Authentication flow management subcommands
 */

import { defineCommand } from 'citty';
import { listCommand } from './list';
import { getCommand } from './get';
import { executionsCommand } from './executions';
import { copyCommand } from './copy';

export const authFlowsCommand = defineCommand({
	meta: {
		name: 'auth-flows',
		description: 'Authentication flow management commands'
	},
	subCommands: {
		list: listCommand,
		get: getCommand,
		executions: executionsCommand,
		copy: copyCommand
	}
});
