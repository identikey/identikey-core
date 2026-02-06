import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportJWK, calculateJwkThumbprint, SignJWT } from 'jose';
import type { KeyLike } from 'jose';
import type { TokenVerificationError as TVEType } from '../errors';

vi.mock('../../keycloak/logger', () => ({
	logger: {
		info: vi.fn(),
		error: vi.fn(),
		debug: vi.fn()
	}
}));

let TEST_JWK: string;
let privateKey: KeyLike;
let kid: string;

const ORIGINAL_ENV = { ...process.env };

const ISSUER = 'https://connect.identikey.io';
const AUDIENCE = 'morphist-mobile';

beforeAll(async () => {
	const keyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	privateKey = keyPair.privateKey;
	const publicJwk = await exportJWK(keyPair.publicKey);
	kid = await calculateJwkThumbprint(publicJwk, 'sha256');
	const privateJwk = await exportJWK(keyPair.privateKey);
	TEST_JWK = JSON.stringify({ ...privateJwk, kid, use: 'sig', alg: 'EdDSA' });
});

beforeEach(() => {
	vi.resetModules();
	process.env = {
		...ORIGINAL_ENV,
		IDENTIKEY_SIGNING_KEY: TEST_JWK,
		IDENTIKEY_ISSUER: ISSUER,
		IDENTIKEY_AUDIENCE: AUDIENCE,
	};
});

afterEach(() => {
	process.env = { ...ORIGINAL_ENV };
});

async function initAndGetModules() {
	const { initializeSigningKey } = await import('./init');
	await initializeSigningKey();
	const { verifyToken } = await import('./verification');
	const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
	return { verifyToken, TokenVerificationError, VerificationFailureCode };
}

async function signToken(overrides?: {
	sub?: string;
	iss?: string;
	aud?: string;
	exp?: number;
	iat?: number;
	useKey?: KeyLike;
	device_id?: string;
	device_trust?: string;
	auth_method?: string;
}): Promise<string> {
	const key = overrides?.useKey ?? privateKey;
	const builder = new SignJWT({
		sub: overrides?.sub ?? 'user-123',
		device_id: overrides?.device_id ?? 'device-abc',
		device_trust: overrides?.device_trust ?? 'verified',
		auth_method: overrides?.auth_method ?? 'passkey',
	})
		.setProtectedHeader({ alg: 'EdDSA', kid })
		.setIssuer(overrides?.iss ?? ISSUER)
		.setAudience(overrides?.aud ?? AUDIENCE)
		.setJti(crypto.randomUUID());

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

describe('verifyToken — success', () => {
	it('returns decoded payload with standard claims', async () => {
		const { verifyToken } = await initAndGetModules();
		const token = await signToken();

		const payload = await verifyToken(token);

		expect(payload.iss).toBe(ISSUER);
		expect(payload.sub).toBe('user-123');
		expect(payload.aud).toBe(AUDIENCE);
		expect(payload.exp).toBeTypeOf('number');
		expect(payload.iat).toBeTypeOf('number');
		expect(payload.jti).toBeTypeOf('string');
	});

	it('returns custom claims (device_id, device_trust, auth_method)', async () => {
		const { verifyToken } = await initAndGetModules();
		const token = await signToken({
			device_id: 'dev-001',
			device_trust: 'high',
			auth_method: 'biometric',
		});

		const payload = await verifyToken(token);

		expect(payload.device_id).toBe('dev-001');
		expect(payload.device_trust).toBe('high');
		expect(payload.auth_method).toBe('biometric');
	});

	it('accepts per-call issuer/audience overrides', async () => {
		const { verifyToken } = await initAndGetModules();
		const customIssuer = 'https://custom.example.com';
		const customAudience = 'custom-app';
		const token = await signToken({ iss: customIssuer, aud: customAudience });

		const payload = await verifyToken(token, {
			issuer: customIssuer,
			audience: customAudience,
		});

		expect(payload.iss).toBe(customIssuer);
		expect(payload.aud).toBe(customAudience);
	});

	it('round-trips with 7.3 signAccessToken', async () => {
		const { initializeSigningKey } = await import('./init');
		await initializeSigningKey();
		const { signAccessToken } = await import('./signing');
		const { verifyToken } = await import('./verification');

		const token = await signAccessToken({
			sub: 'user-999',
			device_id: 'device-round-trip',
			device_trust: 'verified',
			auth_method: 'passkey',
			scope: 'openid profile',
			email: 'test@example.com',
		});

		const payload = await verifyToken(token);

		expect(payload.sub).toBe('user-999');
		expect(payload.device_id).toBe('device-round-trip');
		expect(payload.scope).toBe('openid profile');
		expect(payload.email).toBe('test@example.com');
	});
});

describe('verifyToken — expired token', () => {
	it('throws TokenVerificationError with EXPIRED code', async () => {
		const { verifyToken, TokenVerificationError, VerificationFailureCode } = await initAndGetModules();
		const now = Math.floor(Date.now() / 1000);
		const token = await signToken({ exp: now - 60, iat: now - 120 });

		try {
			await verifyToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.EXPIRED);
		}
	});
});

describe('verifyToken — wrong issuer', () => {
	it('throws TokenVerificationError with INVALID_ISSUER code', async () => {
		const { verifyToken, TokenVerificationError, VerificationFailureCode } = await initAndGetModules();
		const token = await signToken({ iss: 'https://evil.example.com' });

		try {
			await verifyToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_ISSUER);
		}
	});
});

describe('verifyToken — wrong audience', () => {
	it('throws TokenVerificationError with INVALID_AUDIENCE code', async () => {
		const { verifyToken, TokenVerificationError, VerificationFailureCode } = await initAndGetModules();
		const token = await signToken({ aud: 'wrong-audience' });

		try {
			await verifyToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_AUDIENCE);
		}
	});
});

describe('verifyToken — tampered token (invalid signature)', () => {
	it('throws TokenVerificationError with INVALID_SIGNATURE code', async () => {
		const { verifyToken, TokenVerificationError, VerificationFailureCode } = await initAndGetModules();
		const token = await signToken();

		const parts = token.split('.');
		const tamperedPayload = Buffer.from(JSON.stringify({ sub: 'hacked', iss: ISSUER, aud: AUDIENCE }))
			.toString('base64url');
		const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

		try {
			await verifyToken(tampered);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_SIGNATURE);
		}
	});

	it('throws INVALID_SIGNATURE for token signed with different key', async () => {
		const { verifyToken, TokenVerificationError, VerificationFailureCode } = await initAndGetModules();

		const otherKeyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
		const token = await signToken({ useKey: otherKeyPair.privateKey });

		try {
			await verifyToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.INVALID_SIGNATURE);
		}
	});
});

describe('verifyToken — malformed token', () => {
	it('throws TokenVerificationError with MALFORMED code for garbage string', async () => {
		const { verifyToken, TokenVerificationError, VerificationFailureCode } = await initAndGetModules();

		try {
			await verifyToken('not-a-jwt');
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.MALFORMED);
		}
	});

	it('throws TokenVerificationError with MALFORMED code for empty string', async () => {
		const { verifyToken, TokenVerificationError, VerificationFailureCode } = await initAndGetModules();

		try {
			await verifyToken('');
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			expect((err as TVEType).code).toBe(VerificationFailureCode.MALFORMED);
		}
	});
});

describe('verifyToken — uninitialized key', () => {
	it('throws when signing key is not initialized', async () => {
		vi.resetModules();
		process.env = { ...ORIGINAL_ENV, IDENTIKEY_ISSUER: ISSUER, IDENTIKEY_AUDIENCE: AUDIENCE };
		const { verifyToken } = await import('./verification');
		const token = await signToken();

		await expect(verifyToken(token)).rejects.toThrow('Signing key not initialized');
	});
});

describe('TokenVerificationError', () => {
	it('is an instance of Error', async () => {
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const err = new TokenVerificationError('test', VerificationFailureCode.EXPIRED);
		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe('TokenVerificationError');
	});

	it('has code property', async () => {
		const { TokenVerificationError, VerificationFailureCode } = await import('../errors');
		const err = new TokenVerificationError('test', VerificationFailureCode.INVALID_SIGNATURE);
		expect(err.code).toBe('INVALID_SIGNATURE');
	});

	it('does not expose internal jose details in message', async () => {
		const { verifyToken, TokenVerificationError } = await initAndGetModules();
		const now = Math.floor(Date.now() / 1000);
		const token = await signToken({ exp: now - 60, iat: now - 120 });

		try {
			await verifyToken(token);
			expect.fail('Should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(TokenVerificationError);
			const tve = err as TVEType;
			expect(tve.message).toBe('Token has expired');
			expect(tve.message).not.toContain('jose');
		}
	});
});
