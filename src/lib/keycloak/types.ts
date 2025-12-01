/**
 * IdentiKey domain types
 *
 * These types represent the IdentiKey abstraction layer over Keycloak.
 * They hide Keycloak terminology and expose clean domain concepts.
 */

/** Pagination and list options for queries */
export interface ListOptions {
	/** Search filter (username, email, name) */
	search?: string;
	/** Maximum results to return (default 100) */
	max?: number;
	/** Offset for pagination (default 0) */
	offset?: number;
}

/** IdentiKey User domain type */
export interface User {
	id: string;
	username: string;
	email?: string;
	firstName?: string;
	lastName?: string;
	enabled: boolean;
	/** Guild paths the user belongs to (mapped from Keycloak groups) */
	guilds: string[];
	createdTimestamp?: number;
}

/** Input for creating a new user */
export interface CreateUserInput {
	username: string;
	email?: string;
	firstName?: string;
	lastName?: string;
	/** Whether the user is enabled (default true) */
	enabled?: boolean;
}

/** Input for updating an existing user */
export interface UpdateUserInput {
	username?: string;
	email?: string;
	firstName?: string;
	lastName?: string;
	enabled?: boolean;
}

/** User credential information */
export interface Credential {
	id: string;
	type: string;
	userLabel?: string;
	createdDate?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Login Flow Types (Epic 5)
// ─────────────────────────────────────────────────────────────────────────────

/** Authentication flow (e.g., browser, direct-grant) */
export interface LoginFlow {
	id: string;
	alias: string;
	description?: string;
	providerId: string;
	topLevel: boolean;
	builtIn: boolean;
}

/** A single execution step within a login flow */
export interface FlowExecution {
	id: string;
	displayName: string;
	requirement: 'REQUIRED' | 'ALTERNATIVE' | 'CONDITIONAL' | 'DISABLED';
	configurable: boolean;
	providerId?: string;
	/** Nesting depth (0 = top-level) */
	level: number;
	/** Position within this level */
	index: number;
	/** True if this execution is itself a subflow */
	authenticationFlow: boolean;
}

/** Binding types for default flow assignment */
export type FlowBindingType =
	| 'browser'
	| 'direct-grant'
	| 'registration'
	| 'reset-credentials'
	| 'docker-auth';
