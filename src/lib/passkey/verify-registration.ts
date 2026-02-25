import { verifyRegistrationResponse } from '@simplewebauthn/server';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { getChallengeByValue, deleteChallengeByValue } from '$lib/server/challenges';
import { storePasskeyCredential } from './credential-store';
import { getWebAuthnConfig } from './registration-options';
import { PasskeyError, PasskeyErrorCode } from './errors';

export interface VerifyAndStoreParams {
	attestationResponse: RegistrationResponseJSON;
	challenge: string;
	userId: string;
}

export interface StoredPasskeyResult {
	credentialId: string;
	publicKey: string;
	counter: number;
	transports?: string[];
	deviceType: string;
	backedUp: boolean;
	userId: string;
}

function getExpectedOrigins(): string[] {
	const env = process.env.WEBAUTHN_EXPECTED_ORIGIN;
	if (!env) return ['http://localhost:5173'];
	return env.split(',').map((o) => o.trim());
}

export async function verifyAndStorePasskey(
	params: VerifyAndStoreParams
): Promise<StoredPasskeyResult> {
	const { attestationResponse, challenge, userId } = params;

	const challengeRecord = await getChallengeByValue(challenge);
	if (!challengeRecord) {
		throw new PasskeyError(
			'Challenge not found or expired',
			PasskeyErrorCode.CHALLENGE_NOT_FOUND
		);
	}

	if (challengeRecord.userId !== userId) {
		throw new PasskeyError(
			'Challenge does not belong to this user',
			PasskeyErrorCode.CHALLENGE_USER_MISMATCH
		);
	}

	const { rpId } = getWebAuthnConfig();
	const expectedOrigins = getExpectedOrigins();

	let verification;
	try {
		verification = await verifyRegistrationResponse({
			response: attestationResponse,
			expectedChallenge: challenge,
			expectedOrigin: expectedOrigins,
			expectedRPID: rpId
		});
	} catch (err) {
		throw new PasskeyError(
			'Attestation verification failed',
			PasskeyErrorCode.ATTESTATION_INVALID,
			err instanceof Error ? err : new Error(String(err))
		);
	}

	if (!verification.verified || !verification.registrationInfo) {
		throw new PasskeyError(
			'Registration response could not be verified',
			PasskeyErrorCode.VERIFICATION_FAILED
		);
	}

	const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
	const publicKeyBase64 = Buffer.from(credential.publicKey).toString('base64');
	const transports = credential.transports as string[] | undefined;

	let stored;
	try {
		stored = await storePasskeyCredential({
			userId,
			credentialId: credential.id,
			publicKey: publicKeyBase64,
			counter: credential.counter,
			transports,
			deviceType: credentialDeviceType,
			backedUp: credentialBackedUp
		});
	} catch (err) {
		throw new PasskeyError(
			'Failed to store passkey credential',
			PasskeyErrorCode.STORAGE_FAILED,
			err instanceof Error ? err : new Error(String(err))
		);
	}

	await deleteChallengeByValue(challenge);

	return {
		credentialId: credential.id,
		publicKey: publicKeyBase64,
		counter: credential.counter,
		transports,
		deviceType: credentialDeviceType,
		backedUp: credentialBackedUp,
		userId
	};
}
