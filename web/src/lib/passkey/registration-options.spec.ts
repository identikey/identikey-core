import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$lib/server/challenges', () => ({
	createChallenge: vi.fn().mockResolvedValue({
		id: 'challenge-uuid',
		userId: 'user-123',
		challenge: 'mock-challenge',
		type: 'registration',
		expiresAt: new Date(),
		createdAt: new Date()
	})
}));

import { generateRegistrationChallenge, getWebAuthnConfig } from './registration-options';
import { createChallenge } from '$lib/server/challenges';
import { PasskeyErrorCode } from './errors';

beforeEach(() => {
	vi.clearAllMocks();
	process.env.WEBAUTHN_RP_ID = 'localhost';
	process.env.WEBAUTHN_RP_NAME = 'IdentiKey';
});

describe('getWebAuthnConfig', () => {
	it('reads rpId and rpName from env', () => {
		const config = getWebAuthnConfig();
		expect(config.rpId).toBe('localhost');
		expect(config.rpName).toBe('IdentiKey');
	});

	it('defaults rpId to localhost when unset', () => {
		delete process.env.WEBAUTHN_RP_ID;
		const config = getWebAuthnConfig();
		expect(config.rpId).toBe('localhost');
	});

	it('defaults rpName to IdentiKey when unset', () => {
		delete process.env.WEBAUTHN_RP_NAME;
		const config = getWebAuthnConfig();
		expect(config.rpName).toBe('IdentiKey');
	});
});

describe('generateRegistrationChallenge', () => {
	it('returns options with challenge, rp, and user', async () => {
		const options = await generateRegistrationChallenge({ userId: 'user-123' });

		expect(options.challenge).toBeDefined();
		expect(typeof options.challenge).toBe('string');
		expect(options.challenge.length).toBeGreaterThan(0);
		expect(options.rp).toBeDefined();
		expect(options.rp.id).toBe('localhost');
		expect(options.rp.name).toBe('IdentiKey');
		expect(options.user).toBeDefined();
		expect(options.user.name).toBeDefined();
	});

	it('uses userId for user.id (stable identifier)', async () => {
		const options = await generateRegistrationChallenge({
			userId: 'keycloak-user-abc',
			userName: 'alice@example.com',
			displayName: 'Alice'
		});

		expect(options.user.id).toBeDefined();
		expect(typeof options.user.id).toBe('string');
		expect(options.user.name).toBe('alice@example.com');
		expect(options.user.displayName).toBe('Alice');

		const again = await generateRegistrationChallenge({
			userId: 'keycloak-user-abc',
			userName: 'alice@example.com',
			displayName: 'Alice'
		});
		expect(again.user.id).toBe(options.user.id);
	});

	it('produces different user.id for different userIds', async () => {
		const a = await generateRegistrationChallenge({ userId: 'user-aaa' });
		const b = await generateRegistrationChallenge({ userId: 'user-bbb' });
		expect(a.user.id).not.toBe(b.user.id);
	});

	it('falls back to userId for userName/displayName when not provided', async () => {
		const options = await generateRegistrationChallenge({ userId: 'user-xyz' });

		expect(options.user.name).toBe('user-xyz');
		expect(options.user.displayName).toBe('user-xyz');
	});

	it('calls createChallenge with the generated challenge and type registration', async () => {
		const options = await generateRegistrationChallenge({ userId: 'user-123' });

		expect(createChallenge).toHaveBeenCalledTimes(1);
		expect(createChallenge).toHaveBeenCalledWith(
			{
				userId: 'user-123',
				challenge: options.challenge,
				type: 'registration'
			},
			undefined
		);
	});

	it('includes authenticatorSelection preferring platform and discoverable credentials', async () => {
		const options = await generateRegistrationChallenge({ userId: 'user-123' });

		expect(options.authenticatorSelection).toBeDefined();
		expect(options.authenticatorSelection?.residentKey).toBe('preferred');
		expect(options.authenticatorSelection?.authenticatorAttachment).toBe('platform');
		expect(options.authenticatorSelection?.userVerification).toBe('preferred');
	});

	it('includes pubKeyCredParams', async () => {
		const options = await generateRegistrationChallenge({ userId: 'user-123' });

		expect(options.pubKeyCredParams).toBeDefined();
		expect(options.pubKeyCredParams!.length).toBeGreaterThan(0);
	});

	it('includes a timeout', async () => {
		const options = await generateRegistrationChallenge({ userId: 'user-123' });

		expect(options.timeout).toBeDefined();
		expect(typeof options.timeout).toBe('number');
	});

	it('accepts optional excludeCredentials', async () => {
		const options = await generateRegistrationChallenge({
			userId: 'user-123',
			excludeCredentials: [{ id: 'cred-abc', transports: ['internal'] }]
		});

		expect(options.excludeCredentials).toBeDefined();
		expect(options.excludeCredentials).toHaveLength(1);
	});

	it('throws when userId is empty', async () => {
		await expect(generateRegistrationChallenge({ userId: '' })).rejects.toMatchObject({
			name: 'PasskeyError',
			code: PasskeyErrorCode.INVALID_INPUT,
			message: 'userId is required for registration challenge generation'
		});
	});

	it('wraps createChallenge errors with descriptive message', async () => {
		vi.mocked(createChallenge).mockRejectedValueOnce(new Error('connection refused'));

		await expect(generateRegistrationChallenge({ userId: 'user-123' })).rejects.toMatchObject({
			name: 'PasskeyError',
			code: PasskeyErrorCode.STORAGE_FAILED,
			message: 'Failed to persist registration challenge',
			cause: expect.any(Error)
		});
	});

	it('includes supportedAlgorithmIDs (EdDSA, ES256, RS256)', async () => {
		const options = await generateRegistrationChallenge({ userId: 'user-123' });

		const algIds = options.pubKeyCredParams!.map((p) => p.alg);
		expect(algIds).toContain(-8);
		expect(algIds).toContain(-7);
		expect(algIds).toContain(-257);
	});
});
