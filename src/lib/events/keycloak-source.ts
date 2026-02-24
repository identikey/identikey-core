import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type { IdentiKeyEvent, EventFilter, EventProvider, EventSeverity } from './types';

const ERROR_EVENT_TYPES = new Set([
	'LOGIN_ERROR',
	'REGISTER_ERROR',
	'CLIENT_LOGIN_ERROR',
	'FEDERATED_IDENTITY_LINK_ERROR',
	'REMOVE_FEDERATED_IDENTITY_ERROR',
	'UPDATE_ERROR',
	'DELETE_ERROR'
]);

const WARN_EVENT_TYPES = new Set([
	'LOGOUT',
	'REVOKE_GRANT',
	'REMOVE_TOTP',
	'UPDATE_PASSWORD'
]);

function classifySeverity(eventType: string): EventSeverity {
	if (ERROR_EVENT_TYPES.has(eventType)) return 'error';
	if (WARN_EVENT_TYPES.has(eventType)) return 'warn';
	return 'info';
}

function mapLoginEvent(e: Record<string, unknown>): IdentiKeyEvent {
	const type = (e.type as string) ?? 'UNKNOWN';
	return {
		id: `kc-login-${e.time}-${e.type}-${e.userId ?? 'anon'}`,
		timestamp: (e.time as number) ?? Date.now(),
		source: 'keycloak',
		category: 'auth',
		type,
		severity: classifySeverity(type),
		userId: e.userId as string | undefined,
		clientId: e.clientId as string | undefined,
		ipAddress: e.ipAddress as string | undefined,
		details: (e.details as Record<string, string>) ?? {},
		error: e.error as string | undefined
	};
}

function mapAdminEvent(e: Record<string, unknown>): IdentiKeyEvent {
	const opType = (e.operationType as string) ?? 'UNKNOWN';
	const resourceType = (e.resourceType as string) ?? '';
	const type = resourceType ? `${opType}:${resourceType}` : opType;

	const authDetails = (e.authDetails as Record<string, unknown>) ?? {};

	return {
		id: `kc-admin-${e.time}-${opType}-${e.resourcePath ?? ''}`,
		timestamp: (e.time as number) ?? Date.now(),
		source: 'keycloak',
		category: 'admin',
		type,
		severity: opType === 'DELETE' ? 'warn' : 'info',
		userId: authDetails.userId as string | undefined,
		clientId: authDetails.clientId as string | undefined,
		ipAddress: authDetails.ipAddress as string | undefined,
		details: {
			resourcePath: (e.resourcePath as string) ?? '',
			...(e.representation ? { representation: e.representation as string } : {})
		}
	};
}

function matchesFilter(event: IdentiKeyEvent, filter: EventFilter): boolean {
	if (filter.type && event.type !== filter.type) return false;
	if (filter.clientId && event.clientId !== filter.clientId) return false;
	if (filter.userId && event.userId !== filter.userId) return false;
	if (filter.source && event.source !== filter.source) return false;
	if (filter.category && event.category !== filter.category) return false;
	if (filter.severity && event.severity !== filter.severity) return false;
	if (filter.from && event.timestamp < filter.from) return false;
	if (filter.to && event.timestamp > filter.to) return false;
	return true;
}

export class KeycloakEventSource implements EventProvider {
	constructor(
		private client: KcAdminClient,
		private realm: string
	) {}

	async query(filter: EventFilter): Promise<IdentiKeyEvent[]> {
		const max = filter.max ?? 50;

		const [loginEvents, adminEvents] = await Promise.all([
			this.fetchLoginEvents(filter, max),
			this.fetchAdminEvents(filter, max)
		]);

		const all = [...loginEvents, ...adminEvents]
			.filter((e) => matchesFilter(e, filter))
			.sort((a, b) => b.timestamp - a.timestamp)
			.slice(0, max);

		return all;
	}

	async *tail(
		filter: EventFilter,
		signal: AbortSignal,
		intervalMs = 2000
	): AsyncGenerator<IdentiKeyEvent> {
		const seen = new Set<string>();
		let lastPoll = Date.now();

		// Seed the seen set with recent events to avoid replaying history
		const initial = await this.query({ ...filter, max: 100, from: lastPoll - 60_000 });
		for (const e of initial) seen.add(e.id);

		while (!signal.aborted) {
			await sleep(intervalMs, signal);
			if (signal.aborted) break;

			const events = await this.query({ ...filter, max: 100, from: lastPoll - 5000 });
			lastPoll = Date.now();

			// Yield only unseen events, oldest first
			const fresh = events.filter((e) => !seen.has(e.id)).reverse();
			for (const e of fresh) {
				seen.add(e.id);
				yield e;
			}

			// Cap the seen set to prevent unbounded growth
			if (seen.size > 10_000) {
				const arr = [...seen];
				arr.splice(0, arr.length - 5_000);
				seen.clear();
				for (const id of arr) seen.add(id);
			}
		}
	}

	private async fetchLoginEvents(
		filter: EventFilter,
		max: number
	): Promise<IdentiKeyEvent[]> {
		try {
			const params: Record<string, unknown> = {
				realm: this.realm,
				max,
				...(filter.type && !filter.type.includes(':') ? { type: filter.type } : {}),
				...(filter.clientId ? { client: filter.clientId } : {}),
				...(filter.userId ? { user: filter.userId } : {}),
				...(filter.from ? { dateFrom: new Date(filter.from).toISOString().split('T')[0] } : {}),
				...(filter.to ? { dateTo: new Date(filter.to).toISOString().split('T')[0] } : {})
			};

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const events = await (this.client as any).realms.findEvents(params);
			return (events as Record<string, unknown>[]).map(mapLoginEvent);
		} catch {
			return [];
		}
	}

	private async fetchAdminEvents(
		filter: EventFilter,
		max: number
	): Promise<IdentiKeyEvent[]> {
		if (filter.category === 'auth') return [];

		try {
			const params: Record<string, unknown> = {
				realm: this.realm,
				max,
				...(filter.from ? { dateFrom: new Date(filter.from).toISOString().split('T')[0] } : {}),
				...(filter.to ? { dateTo: new Date(filter.to).toISOString().split('T')[0] } : {})
			};

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const events = await (this.client as any).realms.findAdminEvents(params);
			return (events as Record<string, unknown>[]).map(mapAdminEvent);
		} catch {
			return [];
		}
	}
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
	return new Promise((resolve) => {
		const timer = setTimeout(resolve, ms);
		signal.addEventListener('abort', () => {
			clearTimeout(timer);
			resolve();
		}, { once: true });
	});
}
