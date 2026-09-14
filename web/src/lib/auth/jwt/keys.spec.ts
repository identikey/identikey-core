import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';
import {
	generateSigningKeyPair,
	computeKeyId,
	loadSigningKey,
	getPublicKeyJwk,
	exportPrivateKeyJwk
} from './keys';
import { InvalidSigningKeyError } from '../errors';

// Generate a valid Ed25519 test key once, reuse across tests
let TEST_JWK: string;

beforeEach(async () => {
	const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	const privateJwk = await exportJWK(privateKey);
	const publicJwk = await exportJWK(publicKey);
	const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
	TEST_JWK = JSON.stringify({ ...privateJwk, kid, use: 'sig', alg: 'EdDSA' });
});

describe('generateSigningKeyPair', () => {
	it('creates a valid EdDSA Ed25519 key pair', async () => {
		const keyPair = await generateSigningKeyPair();

		expect(keyPair.privateKey).toBeDefined();
		expect(keyPair.publicKey).toBeDefined();
		expect(keyPair.kid).toBeDefined();
		expect(typeof keyPair.kid).toBe('string');
		expect(keyPair.kid.length).toBeGreaterThan(0);
	});

	it('generates unique key pairs each call', async () => {
		const kp1 = await generateSigningKeyPair();
		const kp2 = await generateSigningKeyPair();

		expect(kp1.kid).not.toBe(kp2.kid);
	});

	it('private key is exportable in JWK format', async () => {
		const keyPair = await generateSigningKeyPair();
		const jwk = await exportPrivateKeyJwk(keyPair);

		expect(jwk.kty).toBe('OKP');
		expect(jwk.crv).toBe('Ed25519');
		expect(jwk.d).toBeDefined();
		expect(jwk.x).toBeDefined();
		expect(jwk.kid).toBe(keyPair.kid);
		expect(jwk.use).toBe('sig');
		expect(jwk.alg).toBe('EdDSA');
	});

	it('public key is exportable in JWK format', async () => {
		const keyPair = await generateSigningKeyPair();
		const jwk = await exportJWK(keyPair.publicKey);

		expect(jwk.kty).toBe('OKP');
		expect(jwk.crv).toBe('Ed25519');
		expect(jwk.x).toBeDefined();
	});

	it('kid is SHA-256 thumbprint of public key', async () => {
		const keyPair = await generateSigningKeyPair();
		const recomputedKid = await computeKeyId(keyPair.publicKey);

		expect(keyPair.kid).toBe(recomputedKid);
	});
});

describe('computeKeyId', () => {
	it('returns consistent kid for same public key', async () => {
		const keyPair = await generateSigningKeyPair();
		const kid1 = await computeKeyId(keyPair.publicKey);
		const kid2 = await computeKeyId(keyPair.publicKey);

		expect(kid1).toBe(kid2);
	});

	it('returns different kid for different public keys', async () => {
		const kp1 = await generateSigningKeyPair();
		const kp2 = await generateSigningKeyPair();
		const kid1 = await computeKeyId(kp1.publicKey);
		const kid2 = await computeKeyId(kp2.publicKey);

		expect(kid1).not.toBe(kid2);
	});
});

describe('loadSigningKey', () => {
	const ORIGINAL_ENV = { ...process.env };

	beforeEach(() => {
		process.env = { ...ORIGINAL_ENV };
	});

	it('loads a valid Ed25519 key from env', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = TEST_JWK;

		const keyPair = await loadSigningKey();

		expect(keyPair.privateKey).toBeDefined();
		expect(keyPair.publicKey).toBeDefined();
		expect(keyPair.kid).toBeDefined();
		expect(typeof keyPair.kid).toBe('string');
	});

	it('returns structured key object with privateKey, publicKey, kid', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = TEST_JWK;

		const keyPair = await loadSigningKey();

		expect(keyPair).toHaveProperty('privateKey');
		expect(keyPair).toHaveProperty('publicKey');
		expect(keyPair).toHaveProperty('kid');
	});

	it('throws InvalidSigningKeyError when env var is not set', async () => {
		delete process.env.IDENTIKEY_SIGNING_KEY;

		await expect(loadSigningKey()).rejects.toBeInstanceOf(InvalidSigningKeyError);
		await expect(loadSigningKey()).rejects.toMatchObject({
			message: 'IDENTIKEY_SIGNING_KEY environment variable is not set'
		});
	});

	it('throws InvalidSigningKeyError for malformed JSON', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = 'not-valid-json';

		await expect(loadSigningKey()).rejects.toBeInstanceOf(InvalidSigningKeyError);
		await expect(loadSigningKey()).rejects.toMatchObject({
			message: expect.stringContaining('must be valid JSON')
		});
	});

	it('throws InvalidSigningKeyError with cause for parse failures', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = '{invalid json}}}';

		try {
			await loadSigningKey();
			expect.fail('should have thrown');
		} catch (err) {
			expect(err).toBeInstanceOf(InvalidSigningKeyError);
			expect((err as InvalidSigningKeyError).cause).toBeDefined();
		}
	});

	it('throws InvalidSigningKeyError for wrong curve', async () => {
		// Valid JSON but wrong curve
		process.env.IDENTIKEY_SIGNING_KEY = JSON.stringify({
			kty: 'OKP',
			crv: 'Ed448',
			d: 'test',
			x: 'test'
		});

		await expect(loadSigningKey()).rejects.toBeInstanceOf(InvalidSigningKeyError);
		await expect(loadSigningKey()).rejects.toMatchObject({
			message: expect.stringContaining('Invalid key curve')
		});
	});

	it('throws InvalidSigningKeyError for missing d or x fields', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = JSON.stringify({
			kty: 'OKP',
			crv: 'Ed25519'
		});

		await expect(loadSigningKey()).rejects.toBeInstanceOf(InvalidSigningKeyError);
		await expect(loadSigningKey()).rejects.toMatchObject({
			message: expect.stringContaining('missing required fields')
		});
	});

	it('produces same kid as generateSigningKeyPair for same underlying key', async () => {
		// Generate, export JWK, reload — kid should match
		const original = await generateSigningKeyPair();
		const jwk = await exportPrivateKeyJwk(original);
		process.env.IDENTIKEY_SIGNING_KEY = JSON.stringify(jwk);

		const reloaded = await loadSigningKey();
		expect(reloaded.kid).toBe(original.kid);
	});

	it('uses kid from JWK if provided', async () => {
		const parsed = JSON.parse(TEST_JWK);
		const expectedKid = parsed.kid;
		process.env.IDENTIKEY_SIGNING_KEY = TEST_JWK;

		const keyPair = await loadSigningKey();
		expect(keyPair.kid).toBe(expectedKid);
	});
});

describe('getPublicKeyJwk', () => {
	it('returns JWK with all required JWKS fields', async () => {
		const keyPair = await generateSigningKeyPair();
		const jwk = await getPublicKeyJwk(keyPair);

		expect(jwk.kty).toBe('OKP');
		expect(jwk.crv).toBe('Ed25519');
		expect(jwk.x).toBeDefined();
		expect(jwk.kid).toBe(keyPair.kid);
		expect(jwk.use).toBe('sig');
		expect(jwk.alg).toBe('EdDSA');
	});

	it('does not include private key material (d parameter)', async () => {
		const keyPair = await generateSigningKeyPair();
		const jwk = await getPublicKeyJwk(keyPair);

		expect(jwk.d).toBeUndefined();
	});

	it('format is valid for JWKS endpoint consumption', async () => {
		const keyPair = await generateSigningKeyPair();
		const jwk = await getPublicKeyJwk(keyPair);

		// Simulate wrapping in JWKS format
		const jwks = { keys: [jwk] };
		expect(jwks.keys).toHaveLength(1);
		expect(jwks.keys[0].kid).toBeTruthy();
		expect(jwks.keys[0].use).toBe('sig');
		expect(jwks.keys[0].alg).toBe('EdDSA');
	});
});
