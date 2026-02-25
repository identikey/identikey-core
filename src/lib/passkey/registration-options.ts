import { generateRegistrationOptions } from '@simplewebauthn/server';
import type {
	AuthenticatorTransportFuture,
	PublicKeyCredentialCreationOptionsJSON
} from '@simplewebauthn/server';
import { createChallenge } from '$lib/server/challenges';
import type { Db } from '$lib/server/db';

export interface WebAuthnConfig {
	rpId: string;
	rpName: string;
}

export function getWebAuthnConfig(): WebAuthnConfig {
	return {
		rpId: process.env.WEBAUTHN_RP_ID || 'localhost',
		rpName: process.env.WEBAUTHN_RP_NAME || 'IdentiKey'
	};
}

export interface RegistrationChallengeParams {
	userId: string;
	userName?: string;
	displayName?: string;
	excludeCredentials?: Array<{ id: string; transports?: AuthenticatorTransportFuture[] }>;
}

/**
 * Generate WebAuthn registration options and persist the challenge.
 *
 * The returned object is ready to send to the client (via Epic 10 endpoints).
 * The challenge is stored in DB with a 5-minute TTL for later verification (9.3).
 */
export async function generateRegistrationChallenge(
	params: RegistrationChallengeParams,
	db?: Db
): Promise<PublicKeyCredentialCreationOptionsJSON> {
	if (!params.userId) {
		throw new Error('userId is required for registration challenge generation');
	}

	const { rpId, rpName } = getWebAuthnConfig();
	const encoder = new TextEncoder();

	const options = await generateRegistrationOptions({
		rpName,
		rpID: rpId,
		userID: encoder.encode(params.userId),
		userName: params.userName ?? params.userId,
		userDisplayName: params.displayName ?? params.userName ?? params.userId,
		attestationType: 'none',
		authenticatorSelection: {
			residentKey: 'preferred',
			userVerification: 'preferred',
			authenticatorAttachment: 'platform'
		},
		supportedAlgorithmIDs: [-8, -7, -257],
		excludeCredentials: params.excludeCredentials?.map((c) => ({
			id: c.id,
			transports: c.transports
		}))
	});

	try {
		await createChallenge(
			{
				userId: params.userId,
				challenge: options.challenge,
				type: 'registration'
			},
			db
		);
	} catch (cause) {
		throw new Error('Failed to persist registration challenge', { cause });
	}

	return options;
}
