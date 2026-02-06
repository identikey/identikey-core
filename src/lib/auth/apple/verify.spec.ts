import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import type { KeyLike } from 'jose';
import type { TokenVerificationError as TVEType } from '../errors';

const APPLE_ISSUER = 'https://appleid.apple.com';
const AUDIENCE = 'ai.morphist.app';

let privateKey: KeyLike;
let publicKey: KeyLike;

beforeAll(async () => {
	const keyPair = await generateKeyPair('RS256', { extractable: true });
	privateKey = keyPair.privateKey;
	publicKey = keyPair.publicKey;
});

// Mock getAppleJwkSet to return a function that resolves our test public key
vi.mock('../provider-jwks', () => ({
	getAppleJwkSet: () => {
		// Return a key-resolution function compatible with jose.jwtVerify
		return async () => publicKey;
	},
}));

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
	process.env = { ...ORIGINAL_ENV, APPLE_SERVICES_ID: AUDIENCE };
});

afterEach(() => {
	process.env = { ...ORIGINAL_ENV };
});

async function signAppleToken(overrides?: {
	sub?: string;
	iss?: string;
	aud?: string;
	exp?: number;
	iat?: number;
	email?: string;
	email_verified?: boolean;
	is_private_email?: boolean;
	useKey?: KeyLike;
}): Promise<string> {
	const key = overrides?.useKey ?? privateKey;
	const claims: Record<string, unknown> = {
		sub: overrides?.sub ?? 'apple-user-001',
	};
	if (overrides?.email !== undefined) claims.email = overrides.email;
	if (overrides?.email_verified !== undefined) claims.email_verified = overrides.email_verified;
	if (overrides?.is_private_email !== undefined) claims.is_private_email = overrides.is_private_email;

	const builder = new SignJWT(claims)
		.setProtectedHeader({ alg: 'RS256', kid: 'test-kid' })
		.setIssuer(overrides?.iss ?? APPLE_ISSUER)
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

describe('verifyAppleToken — success', () => {
	it('returns sub for a valid token', async () => {
		const { verifyAppleToken } = await import('./verify');
		const token = await signAppleToken();

		const result = await verifyAppleToken(token);

		expect(result.sub).toBe('apple-user-001');
	});

	it('returns email and optional claims when present (first auth)', async () => {
		const { verifyAppleToken } = await import('./verify');
		const token = await signAppleToken({
			email: 'user@example.com',
			email_verified: true,
			is_private_email: false,
		});

		const result = await verifyAppleToken(token);

		expect(result.sub).toBe('apple-user-001');
		expect(result.email).toBe('user@example.com');
		expect(result.email_verified).toBe(true);
		expect(result.is_private_email).toBe(false);
	});

	it('returns undefined for email fields when absent (subsequent auth)', async () => {
		const { verifyAppleToken } = await import('./verify');
		const token = await signAppleToken();

		const result = await verifyAppleToken(token);

		expect(result.sub).toBe('apple-user-001');
		expect(result.email).toBeUndefined();
		expect(result.email_verified).toBeUndefined();
		expect(result.is_private_email).toBeUndefined();
	});

	it('accepts audience from options over env', async () => {
		const { verifyAppleToken } = await import('./verify');
		const customAudience = 'custom.services.id';
		const token = await signAppleToken({ aud: customAudience });

		const result = await verifyAppleToken(token, { audience: customAudience });

		expect(result.sub).toBe('apple-user-001');
	});

	it('returns private relay email correctly', async () => {
		const { verifyAppleToken } = await import('./verify');
		const token = await signAppleToken({
			email: 'abc123@privaterelay.appleid.com',
			email_verified: true,
			is_private_email: true,
		});

		const result = await verifyAppleToken(token);

		expect(result.email).toBe('abc123@privaterelay.appleid.com');
		expect(result.is_private_email).toBe(true);
	});
});

describe('verifyAppleToken — expired token', () => {
	it('throws TokenVerificationError with EXPIRED code', async () => {
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const now = Math.floor(Date.now() / 1000);
		const token = await signAppleToken({ exp: now - 60, iat: now - 120 });

		try {
			await verifyAppleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.EXPIRED);
		}
	});
});

describe('verifyAppleToken — wrong issuer', () => {
	it('throws TokenVerificationError with INVALID_ISSUER code', async () => {
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const token = await signAppleToken({ iss: 'https://evil.example.com' });

		try {
			await verifyAppleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_ISSUER);
		}
	});
});

describe('verifyAppleToken — wrong audience', () => {
	it('throws TokenVerificationError with INVALID_AUDIENCE code', async () => {
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const token = await signAppleToken({ aud: 'wrong-audience' });

		try {
			await verifyAppleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_AUDIENCE);
		}
	});
});

describe('verifyAppleToken — invalid signature', () => {
	it('throws TokenVerificationError with INVALID_SIGNATURE code for tampered token', async () => {
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const token = await signAppleToken();

		const parts = token.split('.');
		const tamperedPayload = Buffer.from(
			JSON.stringify({ sub: 'hacked', iss: APPLE_ISSUER, aud: AUDIENCE }),
		).toString('base64url');
		const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

		try {
			await verifyAppleToken(tampered);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_SIGNATURE);
		}
	});

	it('throws INVALID_SIGNATURE for token signed with different key', async () => {
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const otherKeyPair = await generateKeyPair('RS256', { extractable: true });
		const token = await signAppleToken({ useKey: otherKeyPair.privateKey });

		try {
			await verifyAppleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_SIGNATURE);
		}
	});
});

describe('verifyAppleToken — malformed token', () => {
	it('throws TokenVerificationError with MALFORMED code for garbage string', async () => {
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');

		try {
			await verifyAppleToken('not-a-jwt');
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.MALFORMED);
		}
	});

	it('throws TokenVerificationError with MALFORMED code for empty string', async () => {
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');

		try {
			await verifyAppleToken('');
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.MALFORMED);
		}
	});
});

describe('verifyAppleToken — missing audience configuration', () => {
	it('throws TokenVerificationError when no audience is configured', async () => {
		delete process.env.APPLE_SERVICES_ID;
		const { verifyAppleToken } = await import('./verify');
		const { TokenVerificationError } = await import('../errors');
		const token = await signAppleToken();

		try {
			await verifyAppleToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).message).toContain('audience');
		}
	});
});
