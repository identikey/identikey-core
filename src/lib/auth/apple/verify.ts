import { jwtVerify } from 'jose';
import { getAppleJwkSet } from '../provider-jwks';
import { TokenVerificationError } from '../errors';

const APPLE_ISSUER = 'https://appleid.apple.com';
const CLOCK_TOLERANCE = 5; // seconds

export interface AppleTokenPayload {
	/** Stable user identifier (consistent across tokens for the same user). */
	sub: string;
	/** User's email. Apple only sends this on first authentication — may be absent on subsequent tokens. */
	email?: string;
	/** Whether the email has been verified by Apple. */
	email_verified?: boolean;
	/** Whether the user chose to use Apple's private email relay. */
	is_private_email?: boolean;
}

export interface VerifyAppleTokenOptions {
	/** Apple Services ID (audience). Falls back to env APPLE_SERVICES_ID if not provided. */
	audience?: string;
}

/**
 * Verify an Apple identity token (JWT) against Apple's JWKS.
 *
 * Validates signature, issuer (`https://appleid.apple.com`), audience, and expiration.
 * Returns structured Apple-specific claims on success.
 *
 * @throws {TokenVerificationError} on signature, issuer, audience, expiration, or format failure
 * @throws {ProviderJwksError} if Apple JWKS resolution fails (propagated from getAppleJwkSet)
 */
export async function verifyAppleToken(
	token: string,
	options?: VerifyAppleTokenOptions,
): Promise<AppleTokenPayload> {
	const audience = options?.audience ?? process.env.APPLE_SERVICES_ID;
	if (!audience) {
		throw new TokenVerificationError(
			'Apple Services ID (audience) is required: provide via options.audience or env APPLE_SERVICES_ID',
			'MALFORMED',
		);
	}

	try {
		const { payload } = await jwtVerify(token, getAppleJwkSet(), {
			issuer: APPLE_ISSUER,
			audience,
			clockTolerance: CLOCK_TOLERANCE,
		});

		return {
			sub: payload.sub!,
			email: payload.email as string | undefined,
			email_verified: payload.email_verified as boolean | undefined,
			is_private_email: payload.is_private_email as boolean | undefined,
		};
	} catch (err) {
		if (err instanceof TokenVerificationError) {
			throw err;
		}
		throw TokenVerificationError.fromJoseError(err);
	}
}
