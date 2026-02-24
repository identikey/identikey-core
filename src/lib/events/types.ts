export type EventSource = 'keycloak' | 'identikey';
export type EventCategory = 'auth' | 'admin' | 'system';
export type EventSeverity = 'info' | 'warn' | 'error';

export interface IdentiKeyEvent {
	id: string;
	timestamp: number;
	source: EventSource;
	category: EventCategory;
	type: string;
	severity: EventSeverity;
	userId?: string;
	clientId?: string;
	ipAddress?: string;
	details: Record<string, string>;
	error?: string;
}

export interface EventFilter {
	type?: string;
	clientId?: string;
	userId?: string;
	source?: EventSource;
	category?: EventCategory;
	severity?: EventSeverity;
	from?: number;
	to?: number;
	max?: number;
}

export interface EventProvider {
	/** Fetch events matching filter, newest first */
	query(filter: EventFilter): Promise<IdentiKeyEvent[]>;
	/** Continuously yield new events. Caller is responsible for aborting via signal. */
	tail(filter: EventFilter, signal: AbortSignal, intervalMs?: number): AsyncGenerator<IdentiKeyEvent>;
}
