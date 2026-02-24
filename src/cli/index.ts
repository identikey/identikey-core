#!/usr/bin/env bun
/**
 * IdentiKey CLI Entry Point
 *
 * Main CLI entry point that wires up all subcommands.
 */

import { runMain, defineCommand } from 'citty';
import { usersCommand } from './commands/users';
import { authFlowsCommand } from './commands/auth-flows';
import { clientsCommand } from './commands/clients';
import { eventsCommand } from './commands/events';

const main = defineCommand({
	meta: {
		name: 'kc',
		description: 'IdentiKey Admin CLI'
	},
	subCommands: {
		users: usersCommand,
		'auth-flows': authFlowsCommand,
		clients: clientsCommand,
		events: eventsCommand
	}
});

runMain(main);
