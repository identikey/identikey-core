#!/usr/bin/env bun
/**
 * IdentiKey CLI Entry Point
 *
 * Main CLI entry point that wires up all subcommands.
 */

import { runMain, defineCommand } from 'citty';
import { usersCommand } from './commands/users';

const main = defineCommand({
	meta: {
		name: 'kc',
		description: 'IdentiKey Admin CLI'
	},
	subCommands: {
		users: usersCommand
	}
});

runMain(main);
