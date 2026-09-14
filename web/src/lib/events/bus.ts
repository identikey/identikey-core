import type { IdentiKeyEvent, EventFilter, EventProvider } from './types';

/**
 * EventBus aggregates multiple EventProviders into a single query/tail interface.
 * Currently backed by KeycloakEventSource; future app-level sources slot in via addProvider().
 */
export class EventBus implements EventProvider {
	private providers: EventProvider[] = [];

	addProvider(provider: EventProvider): void {
		this.providers.push(provider);
	}

	async query(filter: EventFilter): Promise<IdentiKeyEvent[]> {
		const max = filter.max ?? 50;
		const results = await Promise.all(this.providers.map((p) => p.query(filter)));

		return results
			.flat()
			.sort((a, b) => b.timestamp - a.timestamp)
			.slice(0, max);
	}

	async *tail(
		filter: EventFilter,
		signal: AbortSignal,
		intervalMs?: number
	): AsyncGenerator<IdentiKeyEvent> {
		// Merge tail streams from all providers via a shared queue
		const queue: IdentiKeyEvent[] = [];
		let resolve: (() => void) | null = null;

		const drainInto = async (gen: AsyncGenerator<IdentiKeyEvent>) => {
			for await (const event of gen) {
				queue.push(event);
				resolve?.();
			}
		};

		const runners = this.providers.map((p) => drainInto(p.tail(filter, signal, intervalMs)));

		// Don't await runners — they run until signal aborts
		void Promise.all(runners);

		while (!signal.aborted) {
			if (queue.length === 0) {
				await new Promise<void>((r) => {
					resolve = r;
					// Wake up periodically in case signal fires between checks
					const t = setTimeout(r, 500);
					signal.addEventListener('abort', () => { clearTimeout(t); r(); }, { once: true });
				});
			}

			while (queue.length > 0) {
				yield queue.shift()!;
			}
		}
	}
}
