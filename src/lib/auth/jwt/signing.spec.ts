import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportJWK, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import type { KeyLike } from 'jose';

vi.mock('../../keycloak/logger', () => ({
	logger: {
		info: vi.fn(),
		error: vi.fn(),
		debug: vi.fn()
	}
}));

let TEST_JWK: string;
let publicKey: KeyLike;

const ORIGINAL_ENV = { ...process.env };

beforeAll(async () => {
	const keyPair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	publicKey = keyPair.publicKey;
	const privateJwk = await exportJWK(keyPair.privateKey);
	const publicJwk = await exportJWK(keyPair.publicKey);
	const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
	TEST_JWK = JSON.stringify({ ...privateJwk, kid, use: 'sig', alg: 'EdDSA' });
});

beforeEach(() => {
	vi.resetModules();
	process.env = {
		...ORIGINAL_ENV,
		IDENTIKEY_SIGNING_KEY: TEST_JWK,
		IDENTIKEY_ISSUER: 'https://connect.identikey.io',
		IDENTIKEY_AUDIENCE: 'morphist-mobile',
	};
});

afterEach(() => {
	process.env = { ...ORIGINAL_ENV };
});

async function initAndGetSigningFns() {
	const { initializeSigningKey } = await import('./init');
	await initializeSigningKey();
	const { signAccessToken, signRefreshToken, signIdToken } = await import('./signing');
	return { signAccessToken, signRefreshToken, signIdToken };
}

describe('signAccessToken', () => {
	it('returns a signed JWT string with correct standard claims', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
		});

		expect(typeof token).toBe('string');
		expect(token.split('.')).toHaveLength(3);

		const payload = decodeJwt(token);
		expect(payload.iss).toBe('https://connect.identikey.io');
		expect(payload.sub).toBe('user-123');
		expect(payload.aud).toBe('morphist-mobile');
		expect(payload.iat).toBeTypeOf('number');
		expect(payload.exp).toBeTypeOf('number');
		expect(payload.jti).toBeTypeOf('string');
		expect((payload.jti as string).length).toBeGreaterThan(0);
	});

	it('includes device_id, device_trust, auth_method claims', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
		});

		const payload = decodeJwt(token);
		expect(payload.device_id).toBe('device-abc');
		expect(payload.device_trust).toBe('verified');
		expect(payload.auth_method).toBe('passkey');
	});

	it('includes optional claims when provided', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
			scope: 'openid profile',
			email: 'user@example.com',
			email_verified: true,
		});

		const payload = decodeJwt(token);
		expect(payload.scope).toBe('openid profile');
		expect(payload.email).toBe('user@example.com');
		expect(payload.email_verified).toBe(true);
	});

	it('omits optional claims when not provided', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
		});

		const payload = decodeJwt(token);
		expect(payload.scope).toBeUndefined();
		expect(payload.email).toBeUndefined();
		expect(payload.email_verified).toBeUndefined();
	});

	it('sets expiry to 15 minutes from iat', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
		});

		const payload = decodeJwt(token);
		const delta = (payload.exp as number) - (payload.iat as number);
		expect(delta).toBe(15 * 60);
	});

	it('sets header alg=EdDSA and kid from signing key', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
		});

		const header = decodeProtectedHeader(token);
		expect(header.alg).toBe('EdDSA');
		expect(header.kid).toBeTypeOf('string');
		expect((header.kid as string).length).toBeGreaterThan(0);
	});

	it('generates unique jti per token', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const claims = {
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
		};

		const token1 = await signAccessToken(claims);
		const token2 = await signAccessToken(claims);

		const jti1 = decodeJwt(token1).jti;
		const jti2 = decodeJwt(token2).jti;
		expect(jti1).not.toBe(jti2);
	});

	it('can be verified with the public key (round-trip)', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
		});

		const result = await jwtVerify(token, publicKey, {
			issuer: 'https://connect.identikey.io',
			audience: 'morphist-mobile',
		});
		expect(result.payload.sub).toBe('user-123');
	});

	it('accepts per-call issuer/audience overrides', async () => {
		const { signAccessToken } = await initAndGetSigningFns();

		const token = await signAccessToken({
			sub: 'user-123',
			device_id: 'device-abc',
			device_trust: 'verified',
			auth_method: 'passkey',
			iss: 'https://custom-issuer.example.com',
			aud: 'custom-audience',
		});

		const payload = decodeJwt(token);
		expect(payload.iss).toBe('https://custom-issuer.example.com');
		expect(payload.aud).toBe('custom-audience');
	});
});

describe('signRefreshToken', () => {
	it('returns a signed JWT with correct claims', async () => {
		const { signRefreshToken } = await initAndGetSigningFns();

		const token = await signRefreshToken({
			sub: 'user-456',
			device_id: 'device-xyz',
		});

		expect(typeof token).toBe('string');
		const payload = decodeJwt(token);
		expect(payload.iss).toBe('https://connect.identikey.io');
		expect(payload.sub).toBe('user-456');
		expect(payload.aud).toBe('morphist-mobile');
		expect(payload.iat).toBeTypeOf('number');
		expect(payload.exp).toBeTypeOf('number');
		expect(payload.jti).toBeTypeOf('string');
		expect(payload.device_id).toBe('device-xyz');
	});

	it('sets expiry to 30 days from iat', async () => {
		const { signRefreshToken } = await initAndGetSigningFns();

		const token = await signRefreshToken({
			sub: 'user-456',
			device_id: 'device-xyz',
		});

		const payload = decodeJwt(token);
		const delta = (payload.exp as number) - (payload.iat as number);
		expect(delta).toBe(30 * 24 * 60 * 60);
	});

	it('sets header alg=EdDSA and kid', async () => {
		const { signRefreshToken } = await initAndGetSigningFns();

		const token = await signRefreshToken({
			sub: 'user-456',
			device_id: 'device-xyz',
		});

		const header = decodeProtectedHeader(token);
		expect(header.alg).toBe('EdDSA');
		expect(header.kid).toBeTypeOf('string');
	});

	it('can be verified with the public key', async () => {
		const { signRefreshToken } = await initAndGetSigningFns();

		const token = await signRefreshToken({
			sub: 'user-456',
			device_id: 'device-xyz',
		});

		const result = await jwtVerify(token, publicKey, {
			issuer: 'https://connect.identikey.io',
			audience: 'morphist-mobile',
		});
		expect(result.payload.sub).toBe('user-456');
	});
});

describe('signIdToken', () => {
	it('returns a signed JWT with correct claims', async () => {
		const { signIdToken } = await initAndGetSigningFns();

		const token = await signIdToken({
			sub: 'user-789',
		});

		expect(typeof token).toBe('string');
		const payload = decodeJwt(token);
		expect(payload.iss).toBe('https://connect.identikey.io');
		expect(payload.sub).toBe('user-789');
		expect(payload.aud).toBe('morphist-mobile');
		expect(payload.iat).toBeTypeOf('number');
		expect(payload.exp).toBeTypeOf('number');
		expect(payload.jti).toBeTypeOf('string');
	});

	it('includes profile claims when provided', async () => {
		const { signIdToken } = await initAndGetSigningFns();

		const token = await signIdToken({
			sub: 'user-789',
			email: 'user@example.com',
			email_verified: true,
			name: 'Test User',
		});

		const payload = decodeJwt(token);
		expect(payload.email).toBe('user@example.com');
		expect(payload.email_verified).toBe(true);
		expect(payload.name).toBe('Test User');
	});

	it('omits profile claims when not provided', async () => {
		const { signIdToken } = await initAndGetSigningFns();

		const token = await signIdToken({
			sub: 'user-789',
		});

		const payload = decodeJwt(token);
		expect(payload.email).toBeUndefined();
		expect(payload.email_verified).toBeUndefined();
		expect(payload.name).toBeUndefined();
	});

	it('sets expiry to 1 hour from iat', async () => {
		const { signIdToken } = await initAndGetSigningFns();

		const token = await signIdToken({
			sub: 'user-789',
		});

		const payload = decodeJwt(token);
		const delta = (payload.exp as number) - (payload.iat as number);
		expect(delta).toBe(60 * 60);
	});

	it('sets header alg=EdDSA and kid', async () => {
		const { signIdToken } = await initAndGetSigningFns();

		const token = await signIdToken({
			sub: 'user-789',
		});

		const header = decodeProtectedHeader(token);
		expect(header.alg).toBe('EdDSA');
		expect(header.kid).toBeTypeOf('string');
	});

	it('can be verified with the public key', async () => {
		const { signIdToken } = await initAndGetSigningFns();

		const token = await signIdToken({
			sub: 'user-789',
		});

		const result = await jwtVerify(token, publicKey, {
			issuer: 'https://connect.identikey.io',
			audience: 'morphist-mobile',
		});
		expect(result.payload.sub).toBe('user-789');
	});
});

describe('signing key not initialized', () => {
	it('throws when signing key is not initialized', async () => {
		vi.resetModules();
		process.env = { ...ORIGINAL_ENV, IDENTIKEY_ISSUER: 'https://connect.identikey.io', IDENTIKEY_AUDIENCE: 'morphist-mobile' };
		// Import signing without initializing key
		const { signAccessToken } = await import('./signing');

		await expect(
			signAccessToken({
				sub: 'user-123',
				device_id: 'device-abc',
				device_trust: 'verified',
				auth_method: 'passkey',
			})
		).rejects.toThrow('Signing key not initialized');
	});
});

describe('issuer/audience configuration', () => {
	it('throws when issuer is not configured and not passed', async () => {
		vi.resetModules();
		process.env = { ...ORIGINAL_ENV, IDENTIKEY_SIGNING_KEY: TEST_JWK, IDENTIKEY_AUDIENCE: 'morphist-mobile' };
		delete process.env.IDENTIKEY_ISSUER;

		const { initializeSigningKey } = await import('./init');
		await initializeSigningKey();
		const { signAccessToken } = await import('./signing');

		await expect(
			signAccessToken({
				sub: 'user-123',
				device_id: 'device-abc',
				device_trust: 'verified',
				auth_method: 'passkey',
			})
		).rejects.toThrow('Issuer not configured');
	});

	it('throws when audience is not configured and not passed', async () => {
		vi.resetModules();
		process.env = { ...ORIGINAL_ENV, IDENTIKEY_SIGNING_KEY: TEST_JWK, IDENTIKEY_ISSUER: 'https://connect.identikey.io' };
		delete process.env.IDENTIKEY_AUDIENCE;

		const { initializeSigningKey } = await import('./init');
		await initializeSigningKey();
		const { signAccessToken } = await import('./signing');

		await expect(
			signAccessToken({
				sub: 'user-123',
				device_id: 'device-abc',
				device_trust: 'verified',
				auth_method: 'passkey',
			})
		).rejects.toThrow('Audience not configured');
	});
});
