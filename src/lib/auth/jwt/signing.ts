import { SignJWT } from 'jose';
import { getSigningKey } from './init';

const ALG = 'EdDSA';

/** Access token lifetime: 15 minutes */
const ACCESS_TOKEN_LIFETIME = 15 * 60;
/** Refresh token lifetime: 30 days */
const REFRESH_TOKEN_LIFETIME = 30 * 24 * 60 * 60;
/** ID token lifetime: 1 hour */
const ID_TOKEN_LIFETIME = 60 * 60;

/** Claims required for access token signing */
export interface AccessTokenClaims {
	sub: string;
	device_id: string;
	device_trust: string;
	auth_method: string;
	scope?: string;
	email?: string;
	email_verified?: boolean;
	iss?: string;
	aud?: string;
}

/** Claims required for refresh token signing */
export interface RefreshTokenClaims {
	sub: string;
	device_id: string;
	iss?: string;
	aud?: string;
}

/** Claims required for ID token signing */
export interface IdTokenClaims {
	sub: string;
	email?: string;
	email_verified?: boolean;
	name?: string;
	iss?: string;
	aud?: string;
}

function getIssuer(override?: string): string {
	const issuer = override ?? process.env.IDENTIKEY_ISSUER;
	if (!issuer) {
		throw new Error('Issuer not configured: set IDENTIKEY_ISSUER env var or pass iss in claims');
	}
	return issuer;
}

function getAudience(override?: string): string {
	const audience = override ?? process.env.IDENTIKEY_AUDIENCE;
	if (!audience) {
		throw new Error('Audience not configured: set IDENTIKEY_AUDIENCE env var or pass aud in claims');
	}
	return audience;
}

/**
 * Sign an access token JWT.
 * Includes: iss, sub, aud, exp, iat, jti, device_id, device_trust, auth_method.
 * Optional: scope, email, email_verified.
 * Lifetime: 15 minutes.
 */
export async function signAccessToken(claims: AccessTokenClaims): Promise<string> {
	const { privateKey, kid } = getSigningKey();
	const { sub, device_id, device_trust, auth_method, scope, email, email_verified, iss, aud } = claims;

	const builder = new SignJWT({
		sub,
		device_id,
		device_trust,
		auth_method,
		...(scope !== undefined && { scope }),
		...(email !== undefined && { email }),
		...(email_verified !== undefined && { email_verified }),
	})
		.setProtectedHeader({ alg: ALG, kid })
		.setIssuer(getIssuer(iss))
		.setAudience(getAudience(aud))
		.setIssuedAt()
		.setExpirationTime(`${ACCESS_TOKEN_LIFETIME}s`)
		.setJti(crypto.randomUUID());

	return builder.sign(privateKey);
}

/**
 * Sign a refresh token JWT.
 * Includes: iss, sub, aud, exp, iat, jti, device_id.
 * Lifetime: 30 days.
 */
export async function signRefreshToken(claims: RefreshTokenClaims): Promise<string> {
	const { privateKey, kid } = getSigningKey();
	const { sub, device_id, iss, aud } = claims;

	const builder = new SignJWT({
		sub,
		device_id,
	})
		.setProtectedHeader({ alg: ALG, kid })
		.setIssuer(getIssuer(iss))
		.setAudience(getAudience(aud))
		.setIssuedAt()
		.setExpirationTime(`${REFRESH_TOKEN_LIFETIME}s`)
		.setJti(crypto.randomUUID());

	return builder.sign(privateKey);
}

/**
 * Sign an ID token JWT.
 * Includes: iss, sub, aud, exp, iat, jti, plus profile claims when provided.
 * Lifetime: 1 hour.
 */
export async function signIdToken(claims: IdTokenClaims): Promise<string> {
	const { privateKey, kid } = getSigningKey();
	const { sub, email, email_verified, name, iss, aud } = claims;

	const builder = new SignJWT({
		sub,
		...(email !== undefined && { email }),
		...(email_verified !== undefined && { email_verified }),
		...(name !== undefined && { name }),
	})
		.setProtectedHeader({ alg: ALG, kid })
		.setIssuer(getIssuer(iss))
		.setAudience(getAudience(aud))
		.setIssuedAt()
		.setExpirationTime(`${ID_TOKEN_LIFETIME}s`)
		.setJti(crypto.randomUUID());

	return builder.sign(privateKey);
}
