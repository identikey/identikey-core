import { jwtVerify } from 'jose';
import type { JWTPayload } from 'jose';
import { getSigningKey } from './init';
import { TokenVerificationError, VerificationFailureCode } from '../errors';

const CLOCK_TOLERANCE = 5; // seconds

export interface VerifyTokenOptions {
	issuer?: string;
	audience?: string | string[];
}

/**
 * Verify a token issued by IdentiKey.
 * Uses the local public key from getSigningKey().
 * Returns the decoded JWT payload or throws TokenVerificationError.
 */
export async function verifyToken(
	token: string,
	options?: VerifyTokenOptions,
): Promise<JWTPayload> {
	const issuer = options?.issuer ?? process.env.IDENTIKEY_ISSUER;
	const audience = options?.audience ?? process.env.IDENTIKEY_AUDIENCE;

	let publicKey;
	try {
		publicKey = getSigningKey().publicKey;
	} catch (err) {
		throw err;
	}

	try {
		const { payload } = await jwtVerify(token, publicKey, {
			...(issuer && { issuer }),
			...(audience && { audience }),
			clockTolerance: CLOCK_TOLERANCE,
		});
		return payload;
	} catch (err) {
		if (err instanceof TokenVerificationError) {
			throw err;
		}
		throw TokenVerificationError.fromJoseError(err);
	}
}
