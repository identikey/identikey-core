import { defineCommand } from 'citty';
import { getEventBus } from '../../../lib/events';
import { printEventsTable, printJson, printError } from '../../utils/output';

export const listCommand = defineCommand({
	meta: {
		name: 'list',
		description: 'List recent events'
	},
	args: {
		type: {
			type: 'string',
			description: 'Filter by event type (e.g. LOGIN, LOGIN_ERROR)'
		},
		client: {
			type: 'string',
			description: 'Filter by clientId'
		},
		user: {
			type: 'string',
			description: 'Filter by userId'
		},
		category: {
			type: 'string',
			description: 'Filter by category (auth, admin)'
		},
		max: {
			type: 'string',
			description: 'Maximum results (default 50)'
		},
		json: {
			type: 'boolean',
			description: 'Output as JSON'
		}
	},
	async run({ args }) {
		try {
			const bus = await getEventBus();
			const events = await bus.query({
				type: args.type,
				clientId: args.client,
				userId: args.user,
				category: args.category as 'auth' | 'admin' | undefined,
				max: args.max ? parseInt(args.max, 10) : undefined
			});

			if (args.json) {
				printJson(events);
			} else {
				printEventsTable(events);
			}
		} catch (error) {
			printError(error);
			process.exitCode = 1;
		}
	}
});
