import { defineCommand } from 'citty';
import { getEventBus } from '../../../lib/events';
import { printEventLine, printError } from '../../utils/output';

export const tailCommand = defineCommand({
	meta: {
		name: 'tail',
		description: 'Follow events in real-time (Ctrl+C to stop)'
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
		interval: {
			type: 'string',
			description: 'Poll interval in ms (default 2000)'
		}
	},
	async run({ args }) {
		try {
			const bus = await getEventBus();
			const ac = new AbortController();

			process.on('SIGINT', () => ac.abort());
			process.on('SIGTERM', () => ac.abort());

			const intervalMs = args.interval ? parseInt(args.interval, 10) : 2000;

			// eslint-disable-next-line no-console
			console.log(`Tailing events (poll ${intervalMs}ms)… Ctrl+C to stop.\n`);

			const stream = bus.tail(
				{
					type: args.type,
					clientId: args.client,
					userId: args.user,
					category: args.category as 'auth' | 'admin' | undefined
				},
				ac.signal,
				intervalMs
			);

			for await (const event of stream) {
				printEventLine(event);
			}
		} catch (error) {
			if ((error as Error).name === 'AbortError') return;
			printError(error);
			process.exitCode = 1;
		}
	}
});
