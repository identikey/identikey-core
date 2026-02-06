/**
 * Bootstrap user provisioning — find or create Keycloak user from verified Apple/Google token payloads.
 * Consumed by Epic 10 provision endpoints; does not issue tokens or generate WebAuthn challenges.
 */

import type KcAdminClient from '@keycloak/keycloak-admin-client';
import type UserRepresentation from '@keycloak/keycloak-admin-client/lib/defs/userRepresentation';
import { getKeycloakClient } from '../../keycloak/client';
import { ErrorCodes, IdentiKeyError } from '../../keycloak/errors';
import type { AppleTokenPayload } from '../apple';
import type { GoogleTokenPayload } from '../google';

const CONNECTIVITY_CODES = new Set([
	'ENOTFOUND',
	'ECONNREFUSED',
	'EAI_AGAIN',
	'ECONNRESET',
	'ETIMEDOUT',
	'EPIPE',
	'EPROTO'
]);

export type ProvisionResult = {
	userId: string;
	isNewUser: boolean;
	email?: string;
	provider: 'apple' | 'google';
};

export const BootstrapProvisionCodes = {
	PROVISION_FAILED: 'PROVISION_FAILED',
	USER_LOOKUP_FAILED: 'USER_LOOKUP_FAILED',
	USER_CREATE_FAILED: 'USER_CREATE_FAILED',
	MISSING_SUB: 'MISSING_SUB'
} as const;

export type BootstrapProvisionCode =
	(typeof BootstrapProvisionCodes)[keyof typeof BootstrapProvisionCodes];

export class BootstrapProvisionError extends Error {
	constructor(
		message: string,
		public readonly code: BootstrapProvisionCode,
		public readonly cause?: Error
	) {
		super(message);
		this.name = 'BootstrapProvisionError';
	}
}

const PROVIDER_ATTR: Record<'apple' | 'google', string> = {
	apple: 'apple_sub',
	google: 'google_sub'
};

function is409(err: unknown): boolean {
	return (err as { response?: { status?: number } }).response?.status === 409;
}

function wrapConnectionError(err: unknown, message: string): IdentiKeyError {
	const code = (err as { code?: string }).code;
	const isConnectivity =
		code && CONNECTIVITY_CODES.has(code);
	return new IdentiKeyError(
		message,
		isConnectivity ? ErrorCodes.CONNECTION_FAILED : ErrorCodes.CONNECTION_FAILED,
		err instanceof Error ? err : undefined
	);
}

/**
 * Find a Keycloak user by provider sub attribute (apple_sub or google_sub).
 */
export async function findUserByProviderSub(
	client: KcAdminClient,
	provider: 'apple' | 'google',
	sub: string
): Promise<UserRepresentation | null> {
	const attrKey = PROVIDER_ATTR[provider];
	const q = `${attrKey}:${sub}`;
	try {
		const users = await client.users.find({ q, exact: true });
		if (users.length === 0) return null;
		if (users.length > 1) {
			// Should not happen; use first
			return users[0];
		}
		return users[0];
	} catch (err) {
		if (err instanceof IdentiKeyError) throw err;
		if (err instanceof BootstrapProvisionError) throw err;
		throw new BootstrapProvisionError(
			'User lookup by provider sub failed',
			BootstrapProvisionCodes.USER_LOOKUP_FAILED,
			err instanceof Error ? err : undefined
		);
	}
}

/**
 * Create a new Keycloak user with provider sub attribute.
 * On 409 conflict, retries findUserByProviderSub and returns that user's ID if found.
 */
export async function createProvisionedUser(
	client: KcAdminClient,
	provider: 'apple' | 'google',
	payload: AppleTokenPayload | GoogleTokenPayload
): Promise<string> {
	const sub = payload.sub;
	const attrKey = PROVIDER_ATTR[provider];
	const username = `${provider}_${sub.substring(0, 20)}`;
	const email = payload.email;
	const emailVerified = payload.email_verified;
	const firstName =
		provider === 'google' && 'name' in payload ? (payload as GoogleTokenPayload).name : undefined;

	try {
		const response = await client.users.create({
			username,
			email,
			firstName,
			enabled: true,
			emailVerified: emailVerified ?? false,
			attributes: { [attrKey]: [sub] }
		});
		return response.id;
	} catch (err) {
		if (err instanceof IdentiKeyError) throw err;
		if (err instanceof BootstrapProvisionError) throw err;
		if (is409(err)) {
			const existing = await findUserByProviderSub(client, provider, sub);
			if (existing?.id) return existing.id;
			throw new BootstrapProvisionError(
				'Conflict creating user; retry lookup did not find user',
				BootstrapProvisionCodes.USER_CREATE_FAILED,
				err instanceof Error ? err : undefined
			);
		}
		throw new BootstrapProvisionError(
			'Failed to create user',
			BootstrapProvisionCodes.USER_CREATE_FAILED,
			err instanceof Error ? err : undefined
		);
	}
}

function getEmail(payload: AppleTokenPayload | GoogleTokenPayload): string | undefined {
	return payload.email;
}

function getFirstName(payload: AppleTokenPayload | GoogleTokenPayload): string | undefined {
	return 'name' in payload ? (payload as GoogleTokenPayload).name : undefined;
}

/**
 * Update existing user profile (email, firstName) when we have new data and user is missing it.
 * Preserves existing attributes and ensures current provider sub is set.
 * Keycloak PUT replaces the resource, so we pass full user rep with merged attributes.
 */
async function updateProfileIfNeeded(
	client: KcAdminClient,
	userId: string,
	provider: 'apple' | 'google',
	payload: AppleTokenPayload | GoogleTokenPayload,
	existing: UserRepresentation
): Promise<void> {
	const attrKey = PROVIDER_ATTR[provider];
	const newEmail = getEmail(payload);
	const newFirstName = getFirstName(payload);
	const hasNewEmail = newEmail !== undefined && newEmail !== '';
	const hasNewName = newFirstName !== undefined && newFirstName !== '';
	const userMissingEmail = !existing.email;
	const userMissingFirstName = !existing.firstName;
	const shouldUpdateEmail = hasNewEmail && userMissingEmail;
	const shouldUpdateName = hasNewName && userMissingFirstName;

	const mergedAttributes: Record<string, string[]> = {
		...(existing.attributes ?? {}),
		[attrKey]: [payload.sub]
	};

	if (!shouldUpdateEmail && !shouldUpdateName && existing.attributes?.[attrKey]?.[0] === payload.sub) {
		return;
	}

	const updatePayload: UserRepresentation = {
		...existing,
		username: existing.username,
		enabled: existing.enabled ?? true,
		email: shouldUpdateEmail ? newEmail : existing.email,
		firstName: shouldUpdateName ? newFirstName : existing.firstName,
		attributes: mergedAttributes
	};
	await client.users.update({ id: userId }, updatePayload);
}

/**
 * Provision a user from a verified Apple or Google token payload.
 * Finds by provider sub; creates if not found. Updates profile when existing user is missing email/name.
 */
export async function provisionUser(
	provider: 'apple' | 'google',
	payload: AppleTokenPayload | GoogleTokenPayload
): Promise<ProvisionResult> {
	if (!payload.sub) {
		throw new BootstrapProvisionError(
			'Token payload is missing sub (required for provisioning)',
			BootstrapProvisionCodes.MISSING_SUB
		);
	}

	let client: KcAdminClient;
	try {
		client = await getKeycloakClient();
	} catch (err) {
		if (err instanceof IdentiKeyError) throw err;
		throw wrapConnectionError(err, 'Failed to connect to Keycloak');
	}

	const existing = await findUserByProviderSub(client, provider, payload.sub);
	if (existing?.id) {
		await updateProfileIfNeeded(client, existing.id, provider, payload, existing);
		return {
			userId: existing.id,
			isNewUser: false,
			email: getEmail(payload) ?? existing.email,
			provider
		};
	}

	const userId = await createProvisionedUser(client, provider, payload);
	return {
		userId,
		isNewUser: true,
		email: getEmail(payload),
		provider
	};
}
