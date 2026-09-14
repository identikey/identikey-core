import { defineCommand } from 'citty';
import { listCommand } from './list';
import { tailCommand } from './tail';
import { enableCommand } from './enable';

export const eventsCommand = defineCommand({
	meta: {
		name: 'events',
		description: 'Event log commands'
	},
	subCommands: {
		list: listCommand,
		tail: tailCommand,
		enable: enableCommand
	}
});
