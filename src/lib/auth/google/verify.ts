import { jwtVerify } from 'jose';
import { getGoogleJwkSet } from '../provider-jwks';
import { TokenVerificationError } from '../errors';

const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_ISSUER_ALT = 'accounts.google.com';
const CLOCK_TOLERANCE = 5;

export interface GoogleTokenPayload {
	/** Stable user identifier (consistent across tokens for the same user). */
	sub: string;
	/** User's email. Google sends profile claims on every token when scopes are granted (unlike Apple). */
	email?: string;
	/** Whether the email has been verified by Google. */
	email_verified?: boolean;
	/** Display name. */
	name?: string;
	/** Profile picture URL. */
	picture?: string;
}

export interface VerifyGoogleTokenOptions {
	/** Google OAuth Client ID (audience). Falls back to env GOOGLE_CLIENT_ID if not provided. */
	audience?: string;
}

/**
 * Verify a Google identity token (JWT) against Google's JWKS.
 *
 * Validates signature, issuer (https://accounts.google.com or accounts.google.com), audience, and expiration.
 * Returns structured Google-specific claims on success.
 *
 * @throws {TokenVerificationError} on signature, issuer, audience, expiration, or format failure
 * @throws {ProviderJwksError} if Google JWKS resolution fails (propagated from getGoogleJwkSet)
 */
export async function verifyGoogleToken(
	token: string,
	options?: VerifyGoogleTokenOptions,
): Promise<GoogleTokenPayload> {
	const audience = options?.audience ?? process.env.GOOGLE_CLIENT_ID;
	if (!audience) {
		throw new TokenVerificationError(
			'Google OAuth Client ID (audience) is required: provide via options.audience or env GOOGLE_CLIENT_ID',
			'MALFORMED',
		);
	}

	try {
		const { payload } = await jwtVerify(token, getGoogleJwkSet(), {
			issuer: [GOOGLE_ISSUER, GOOGLE_ISSUER_ALT],
			audience,
			clockTolerance: CLOCK_TOLERANCE,
		});

		return {
			sub: payload.sub!,
			email: payload.email as string | undefined,
			email_verified: payload.email_verified as boolean | undefined,
			name: payload.name as string | undefined,
			picture: payload.picture as string | undefined,
		};
	} catch (err) {
		if (err instanceof TokenVerificationError) {
			throw err;
		}
		throw TokenVerificationError.fromJoseError(err);
	}
}
