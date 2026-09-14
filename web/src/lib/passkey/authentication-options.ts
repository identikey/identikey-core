import { generateAuthenticationOptions } from '@simplewebauthn/server';
import type {
	AuthenticatorTransportFuture,
	PublicKeyCredentialRequestOptionsJSON
} from '@simplewebauthn/server';
import { createChallenge } from '$lib/server/challenges';
import type { Db } from '$lib/server/db';
import { getWebAuthnConfig } from './registration-options';
import { getPasskeysByUserId } from './credential-store';
import { PasskeyError, PasskeyErrorCode } from './errors';

export interface AuthenticationChallengeParams {
	userId?: string;
}

const VALID_TRANSPORTS = new Set<AuthenticatorTransportFuture>([
	'ble',
	'cable',
	'hybrid',
	'internal',
	'nfc',
	'smart-card',
	'usb'
]);

function parseStoredTransports(
	transports: string | null
): AuthenticatorTransportFuture[] | undefined {
	if (!transports) {
		return undefined;
	}

	try {
		const parsed = JSON.parse(transports);
		if (!Array.isArray(parsed) || parsed.some((value) => !VALID_TRANSPORTS.has(value))) {
			throw new Error('Stored transports must be an array of valid authenticator transports');
		}

		return parsed;
	} catch (cause) {
		throw new PasskeyError(
			'Stored passkey transports are invalid',
			PasskeyErrorCode.INVALID_PASSKEY_DATA,
			cause instanceof Error ? cause : undefined
		);
	}
}

/**
 * Generate WebAuthn authentication options and persist the challenge.
 *
 * If `userId` is provided, looks up the user's stored passkeys and
 * populates `allowCredentials`. If the user has no passkeys, throws.
 *
 * If no `userId`, omits `allowCredentials` for discoverable credential flow.
 */
export async function generateAuthenticationChallenge(
	params?: AuthenticationChallengeParams,
	db?: Db
): Promise<PublicKeyCredentialRequestOptionsJSON> {
	const { rpId } = getWebAuthnConfig();
	const providedUserId = params?.userId;

	if (providedUserId !== undefined && providedUserId.trim().length === 0) {
		throw new PasskeyError(
			'userId must be a non-empty string when provided',
			PasskeyErrorCode.INVALID_INPUT
		);
	}

	const userId = providedUserId ?? null;

	let allowCredentials:
		| Array<{ id: string; transports?: AuthenticatorTransportFuture[] }>
		| undefined;

	if (providedUserId !== undefined) {
		const passkeys = await getPasskeysByUserId(providedUserId, db);
		if (passkeys.length === 0) {
			throw new PasskeyError(
				'No passkeys found for the requested user',
				PasskeyErrorCode.NO_PASSKEYS_FOUND
			);
		}
		allowCredentials = passkeys.map((pk) => ({
			id: pk.credentialId,
			transports: parseStoredTransports(pk.transports)
		}));
	}

	const options = await generateAuthenticationOptions({
		rpID: rpId,
		allowCredentials,
		userVerification: 'preferred'
	});

	try {
		await createChallenge(
			{
				userId,
				challenge: options.challenge,
				type: 'authentication'
			},
			db
		);
	} catch (cause) {
		throw new PasskeyError(
			'Failed to persist authentication challenge',
			PasskeyErrorCode.STORAGE_FAILED,
			cause instanceof Error ? cause : undefined
		);
	}

	return options;
}
