import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture
} from '@simplewebauthn/server';
import { getChallengeByValue, deleteChallengeByValue } from '$lib/server/challenges';
import { getPasskeyByCredentialId, updatePasskeyCounter } from './credential-store';
import { getWebAuthnConfig } from './registration-options';
import { PasskeyError, PasskeyErrorCode } from './errors';

export interface VerifyAuthenticationParams {
	assertionResponse: AuthenticationResponseJSON;
	challenge: string;
}

export interface AuthenticationResult {
	userId: string;
	credentialId: string;
	newCounter: number;
}

function getExpectedOrigins(): string[] {
	const env = process.env.WEBAUTHN_EXPECTED_ORIGIN;
	if (!env) return ['http://localhost:5173'];
	return env.split(',').map((o) => o.trim());
}

function parseTransports(stored: string | null): AuthenticatorTransportFuture[] | undefined {
	if (!stored) return undefined;
	try {
		const parsed = JSON.parse(stored);
		return Array.isArray(parsed) ? (parsed as AuthenticatorTransportFuture[]) : undefined;
	} catch {
		// A malformed transports column must not block a valid assertion — transports
		// are a UI hint to the authenticator, not part of the security decision.
		return undefined;
	}
}

export async function verifyAuthenticationAssertion(
	params: VerifyAuthenticationParams
): Promise<AuthenticationResult> {
	const { assertionResponse, challenge } = params;

	const challengeRecord = await getChallengeByValue(challenge);
	if (!challengeRecord) {
		throw new PasskeyError('Challenge not found or expired', PasskeyErrorCode.CHALLENGE_NOT_FOUND);
	}

	const credentialId = assertionResponse.id;
	const credential = await getPasskeyByCredentialId(credentialId);
	if (!credential) {
		throw new PasskeyError('Credential not found', PasskeyErrorCode.CREDENTIAL_NOT_FOUND);
	}

	// Known-user flow only. In the discoverable-credential flow the challenge carries
	// no userId — the credential record itself establishes who is authenticating.
	if (challengeRecord.userId !== null && credential.userId !== challengeRecord.userId) {
		throw new PasskeyError(
			'Challenge does not belong to this credential',
			PasskeyErrorCode.CHALLENGE_USER_MISMATCH
		);
	}

	const { rpId } = getWebAuthnConfig();
	const expectedOrigins = getExpectedOrigins();

	let verification;
	try {
		verification = await verifyAuthenticationResponse({
			response: assertionResponse,
			expectedChallenge: challenge,
			expectedOrigin: expectedOrigins,
			expectedRPID: rpId,
			credential: {
				id: credential.credentialId,
				publicKey: Buffer.from(credential.publicKey, 'base64'),
				counter: credential.counter,
				transports: parseTransports(credential.transports)
			}
		});
	} catch (err) {
		throw new PasskeyError(
			'Assertion verification failed',
			PasskeyErrorCode.ASSERTION_INVALID,
			err instanceof Error ? err : new Error(String(err))
		);
	}

	if (!verification.verified || !verification.authenticationInfo) {
		throw new PasskeyError(
			'Authentication response could not be verified',
			PasskeyErrorCode.VERIFICATION_FAILED
		);
	}

	const { newCounter } = verification.authenticationInfo;

	// Replay protection: the counter must be persisted before the caller acts on the
	// result, so a failure here is fatal rather than swallowed.
	try {
		await updatePasskeyCounter(credentialId, newCounter);
	} catch (err) {
		throw new PasskeyError(
			'Failed to update credential counter',
			PasskeyErrorCode.STORAGE_FAILED,
			err instanceof Error ? err : new Error(String(err))
		);
	}

	try {
		await deleteChallengeByValue(challenge);
	} catch {
		// Credential is already verified — swallow deletion failure to avoid
		// surfacing a misleading error. The challenge will expire naturally.
	}

	return {
		userId: credential.userId,
		credentialId,
		newCounter
	};
}
