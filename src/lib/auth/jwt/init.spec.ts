import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose';

vi.mock('../../keycloak/logger', () => ({
	logger: {
		info: vi.fn(),
		error: vi.fn(),
		debug: vi.fn()
	}
}));

// Must import after mock setup
const { logger } = await import('../../keycloak/logger');

let TEST_JWK: string;

beforeEach(async () => {
	vi.resetModules();
	const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
	const privateJwk = await exportJWK(privateKey);
	const publicJwk = await exportJWK(publicKey);
	const kid = await calculateJwkThumbprint(publicJwk, 'sha256');
	TEST_JWK = JSON.stringify({ ...privateJwk, kid, use: 'sig', alg: 'EdDSA' });
	(logger.info as ReturnType<typeof vi.fn>).mockClear();
	(logger.error as ReturnType<typeof vi.fn>).mockClear();
});

describe('initializeSigningKey', () => {
	const ORIGINAL_ENV = { ...process.env };

	beforeEach(() => {
		process.env = { ...ORIGINAL_ENV };
	});

	it('loads and returns signing key with valid env var', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = TEST_JWK;
		const { initializeSigningKey } = await import('./init');

		const keyPair = await initializeSigningKey();

		expect(keyPair).toBeDefined();
		expect(keyPair.privateKey).toBeDefined();
		expect(keyPair.publicKey).toBeDefined();
		expect(keyPair.kid).toBeDefined();
		expect(logger.info).toHaveBeenCalledWith(
			expect.objectContaining({ kid: keyPair.kid }),
			'Signing key loaded successfully'
		);
	});

	it('logs error and exits when env var is not set', async () => {
		delete process.env.IDENTIKEY_SIGNING_KEY;
		const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
			throw new Error('process.exit called');
		});

		const { initializeSigningKey } = await import('./init');

		await expect(initializeSigningKey()).rejects.toThrow('process.exit called');
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ error: expect.stringContaining('not set') }),
			'Failed to load signing key'
		);
		expect(mockExit).toHaveBeenCalledWith(1);

		mockExit.mockRestore();
	});

	it('logs error and exits when key is invalid JSON', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = 'not-valid-json';
		const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
			throw new Error('process.exit called');
		});

		const { initializeSigningKey } = await import('./init');

		await expect(initializeSigningKey()).rejects.toThrow('process.exit called');
		expect(logger.error).toHaveBeenCalledWith(
			expect.objectContaining({ error: expect.stringContaining('must be valid JSON') }),
			'Failed to load signing key'
		);
		expect(mockExit).toHaveBeenCalledWith(1);

		mockExit.mockRestore();
	});

	it('does not log private key material', async () => {
		process.env.IDENTIKEY_SIGNING_KEY = TEST_JWK;
		const { initializeSigningKey } = await import('./init');

		await initializeSigningKey();

		// Verify no log call contains the JWK "d" parameter (private key)
		const parsedJwk = JSON.parse(TEST_JWK);
		for (const call of (logger.info as ReturnType<typeof vi.fn>).mock.calls) {
			const logStr = JSON.stringify(call);
			expect(logStr).not.toContain(parsedJwk.d);
			expect(logStr).not.toContain(TEST_JWK);
		}
		expect(true).toBe(true);
	});
});

describe('getSigningKey', () => {
	it('throws if not initialized', async () => {
		// Fresh import with no initialization
		vi.resetModules();
		const { getSigningKey } = await import('./init');

		expect(() => getSigningKey()).toThrow('Signing key not initialized');
	});
});
