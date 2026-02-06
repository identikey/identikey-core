import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, SignJWT } from 'jose';
import type { KeyLike } from 'jose';
import type { TokenVerificationError as TVEType } from '../errors';

const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_ISSUER_ALT = 'accounts.google.com';
const AUDIENCE = '123456789-abc.apps.googleusercontent.com';

let privateKey: KeyLike;
let publicKey: KeyLike;

beforeAll(async () => {
	const keyPair = await generateKeyPair('RS256', { extractable: true });
	privateKey = keyPair.privateKey;
	publicKey = keyPair.publicKey;
});

vi.mock('../provider-jwks', () => ({
	getGoogleJwkSet: () => async () => publicKey,
}));

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
	process.env = { ...ORIGINAL_ENV, GOOGLE_CLIENT_ID: AUDIENCE };
});

afterEach(() => {
	process.env = { ...ORIGINAL_ENV };
});

async function signGoogleToken(overrides?: {
	sub?: string;
	iss?: string;
	aud?: string;
	exp?: number;
	iat?: number;
	email?: string;
	email_verified?: boolean;
	name?: string;
	picture?: string;
	useKey?: KeyLike;
}): Promise<string> {
	const key = overrides?.useKey ?? privateKey;
	const claims: Record<string, unknown> = {
		sub: overrides?.sub ?? 'google-user-001',
	};
	if (overrides?.email !== undefined) claims.email = overrides.email;
	if (overrides?.email_verified !== undefined) claims.email_verified = overrides.email_verified;
	if (overrides?.name !== undefined) claims.name = overrides.name;
	if (overrides?.picture !== undefined) claims.picture = overrides.picture;

	const builder = new SignJWT(claims)
		.setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
		.setIssuer(overrides?.iss ?? GOOGLE_ISSUER)
		.setAudience(overrides?.aud ?? AUDIENCE);

	if (overrides?.iat !== undefined) {
		builder.setIssuedAt(overrides.iat);
	} else {
		builder.setIssuedAt();
	}

	if (overrides?.exp !== undefined) {
		builder.setExpirationTime(overrides.exp);
	} else {
		builder.setExpirationTime('15m');
	}

	return builder.sign(key);
}

describe('verifyGoogleToken — success', () => {
	it('returns sub for a valid token', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const token = await signGoogleToken();

		const result = await verifyGoogleToken(token);

		expect(result.sub).toBe('google-user-001');
	});

	it('returns all profile claims when present', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const token = await signGoogleToken({
			email: 'user@gmail.com',
			email_verified: true,
			name: 'Test User',
			picture: 'https://lh3.googleusercontent.com/photo',
		});

		const result = await verifyGoogleToken(token);

		expect(result.sub).toBe('google-user-001');
		expect(result.email).toBe('user@gmail.com');
		expect(result.email_verified).toBe(true);
		expect(result.name).toBe('Test User');
		expect(result.picture).toBe('https://lh3.googleusercontent.com/photo');
	});

	it('returns undefined for optional claims when absent', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const token = await signGoogleToken();

		const result = await verifyGoogleToken(token);

		expect(result.sub).toBe('google-user-001');
		expect(result.email).toBeUndefined();
		expect(result.email_verified).toBeUndefined();
		expect(result.name).toBeUndefined();
		expect(result.picture).toBeUndefined();
	});

	it('accepts audience from options over env', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const customAudience = 'custom-client-id.apps.googleusercontent.com';
		const token = await signGoogleToken({ aud: customAudience });

		const result = await verifyGoogleToken(token, { audience: customAudience });

		expect(result.sub).toBe('google-user-001');
	});

	it('accepts issuer https://accounts.google.com', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const token = await signGoogleToken({ iss: GOOGLE_ISSUER });

		const result = await verifyGoogleToken(token);

		expect(result.sub).toBe('google-user-001');
	});

	it('accepts issuer accounts.google.com (alternate format)', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const token = await signGoogleToken({ iss: GOOGLE_ISSUER_ALT });

		const result = await verifyGoogleToken(token);

		expect(result.sub).toBe('google-user-001');
	});
});

describe('verifyGoogleToken — expired token', () => {
	it('throws TokenVerificationError with EXPIRED code', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const now = Math.floor(Date.now() / 1000);
		const token = await signGoogleToken({ exp: now - 60, iat: now - 120 });

		try {
			await verifyGoogleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.EXPIRED);
		}
	});
});

describe('verifyGoogleToken — wrong issuer', () => {
	it('throws TokenVerificationError with INVALID_ISSUER code', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const token = await signGoogleToken({ iss: 'https://evil.example.com' });

		try {
			await verifyGoogleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_ISSUER);
		}
	});
});

describe('verifyGoogleToken — wrong audience', () => {
	it('throws TokenVerificationError with INVALID_AUDIENCE code', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const token = await signGoogleToken({ aud: 'wrong-audience' });

		try {
			await verifyGoogleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_AUDIENCE);
		}
	});
});

describe('verifyGoogleToken — invalid signature', () => {
	it('throws TokenVerificationError with INVALID_SIGNATURE code for tampered token', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const token = await signGoogleToken();

		const parts = token.split('.');
		const tamperedPayload = Buffer.from(
			JSON.stringify({ sub: 'hacked', iss: GOOGLE_ISSUER, aud: AUDIENCE }),
		).toString('base64url');
		const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

		try {
			await verifyGoogleToken(tampered);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_SIGNATURE);
		}
	});

	it('throws INVALID_SIGNATURE for token signed with different key', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const otherKeyPair = await generateKeyPair('RS256', { extractable: true });
		const token = await signGoogleToken({ useKey: otherKeyPair.privateKey });

		try {
			await verifyGoogleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_SIGNATURE);
		}
	});
});

describe('verifyGoogleToken — malformed token', () => {
	it('throws TokenVerificationError with MALFORMED code for garbage string', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');

		try {
			await verifyGoogleToken('not-a-jwt');
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.MALFORMED);
		}
	});

	it('throws TokenVerificationError with MALFORMED code for empty string', async () => {
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');

		try {
			await verifyGoogleToken('');
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.MALFORMED);
		}
	});
});

describe('verifyGoogleToken — missing audience configuration', () => {
	it('throws TokenVerificationError when no audience is configured', async () => {
		delete process.env.GOOGLE_CLIENT_ID;
		const { verifyGoogleToken } = await import('./verify');
		const { TokenVerificationError } = await import('../errors');
		const token = await signGoogleToken();

		try {
			await verifyGoogleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).message).toContain('audience');
		}
	});
});
