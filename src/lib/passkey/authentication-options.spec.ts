import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$lib/server/challenges', () => ({
	createChallenge: vi.fn().mockResolvedValue({
		id: 'challenge-uuid',
		userId: 'user-123',
		challenge: 'mock-challenge',
		type: 'authentication',
		expiresAt: new Date(),
		createdAt: new Date()
	})
}));

vi.mock('./credential-store', () => ({
	getPasskeysByUserId: vi.fn().mockResolvedValue([])
}));

vi.mock('@simplewebauthn/server', () => ({
	generateAuthenticationOptions: vi.fn().mockResolvedValue({
		challenge: 'mock-auth-challenge-b64url',
		rpId: 'localhost',
		timeout: 60000,
		userVerification: 'preferred'
	})
}));

import { generateAuthenticationChallenge } from './authentication-options';
import { createChallenge } from '$lib/server/challenges';
import { getPasskeysByUserId } from './credential-store';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { PasskeyError, PasskeyErrorCode } from './errors';

beforeEach(() => {
	vi.clearAllMocks();
	process.env.WEBAUTHN_RP_ID = 'localhost';
	process.env.WEBAUTHN_RP_NAME = 'IdentiKey';

	vi.mocked(generateAuthenticationOptions).mockResolvedValue({
		challenge: 'mock-auth-challenge-b64url',
		rpId: 'localhost',
		timeout: 60000,
		userVerification: 'preferred'
	});
});

describe('generateAuthenticationChallenge', () => {
	describe('known user with passkeys', () => {
		const mockPasskeys = [
			{
				id: 'pk-1',
				userId: 'user-123',
				credentialId: 'cred-aaa',
				publicKey: 'pk-data',
				counter: 5,
				transports: '["internal","hybrid"]',
				deviceType: 'multiDevice',
				backedUp: true,
				createdAt: new Date(),
				lastUsedAt: null
			},
			{
				id: 'pk-2',
				userId: 'user-123',
				credentialId: 'cred-bbb',
				publicKey: 'pk-data-2',
				counter: 0,
				transports: null,
				deviceType: 'singleDevice',
				backedUp: false,
				createdAt: new Date(),
				lastUsedAt: null
			}
		];

		beforeEach(() => {
			vi.mocked(getPasskeysByUserId).mockResolvedValue(mockPasskeys);
		});

		it('calls generateAuthenticationOptions with allowCredentials from stored passkeys', async () => {
			await generateAuthenticationChallenge({ userId: 'user-123' });

			expect(generateAuthenticationOptions).toHaveBeenCalledWith({
				rpID: 'localhost',
				allowCredentials: [
					{ id: 'cred-aaa', transports: ['internal', 'hybrid'] },
					{ id: 'cred-bbb', transports: undefined }
				],
				userVerification: 'preferred'
			});
		});

		it('stores challenge with type authentication and the userId', async () => {
			await generateAuthenticationChallenge({ userId: 'user-123' });

			expect(createChallenge).toHaveBeenCalledWith(
				{
					userId: 'user-123',
					challenge: 'mock-auth-challenge-b64url',
					type: 'authentication'
				},
				undefined
			);
		});

		it('returns the generated options', async () => {
			const options = await generateAuthenticationChallenge({ userId: 'user-123' });

			expect(options.challenge).toBe('mock-auth-challenge-b64url');
			expect(options.rpId).toBe('localhost');
			expect(options.userVerification).toBe('preferred');
		});

		it('passes db parameter through to getPasskeysByUserId and createChallenge', async () => {
			const fakeDb = {} as any;
			await generateAuthenticationChallenge({ userId: 'user-123' }, fakeDb);

			expect(getPasskeysByUserId).toHaveBeenCalledWith('user-123', fakeDb);
			expect(createChallenge).toHaveBeenCalledWith(
				expect.objectContaining({ userId: 'user-123' }),
				fakeDb
			);
		});
	});

	describe('discoverable credential flow (no userId)', () => {
		it('omits allowCredentials when no userId provided', async () => {
			await generateAuthenticationChallenge();

			expect(generateAuthenticationOptions).toHaveBeenCalledWith({
				rpID: 'localhost',
				allowCredentials: undefined,
				userVerification: 'preferred'
			});
		});

		it('does not look up passkeys when no userId', async () => {
			await generateAuthenticationChallenge();

			expect(getPasskeysByUserId).not.toHaveBeenCalled();
		});

		it('stores challenge with null userId', async () => {
			await generateAuthenticationChallenge();

			expect(createChallenge).toHaveBeenCalledWith(
				{
					userId: null,
					challenge: 'mock-auth-challenge-b64url',
					type: 'authentication'
				},
				undefined
			);
		});

		it('also works with empty params object', async () => {
			await generateAuthenticationChallenge({});

			expect(generateAuthenticationOptions).toHaveBeenCalledWith({
				rpID: 'localhost',
				allowCredentials: undefined,
				userVerification: 'preferred'
			});
			expect(createChallenge).toHaveBeenCalledWith(
				expect.objectContaining({ userId: null }),
				undefined
			);
		});
	});

	describe('error handling', () => {
		it('throws NO_PASSKEYS_FOUND when user has no passkeys', async () => {
			vi.mocked(getPasskeysByUserId).mockResolvedValue([]);

			await expect(
				generateAuthenticationChallenge({ userId: 'user-no-keys' })
			).rejects.toMatchObject({
				name: 'PasskeyError',
				code: PasskeyErrorCode.NO_PASSKEYS_FOUND,
				message: 'No passkeys found for the requested user'
			});
		});

		it('throws STORAGE_FAILED when createChallenge fails', async () => {
			vi.mocked(createChallenge).mockRejectedValueOnce(new Error('db down'));

			await expect(generateAuthenticationChallenge()).rejects.toMatchObject({
				name: 'PasskeyError',
				code: PasskeyErrorCode.STORAGE_FAILED,
				message: 'Failed to persist authentication challenge',
				cause: expect.any(Error)
			});
		});

		it('does not call createChallenge if user has no passkeys', async () => {
			vi.mocked(getPasskeysByUserId).mockResolvedValue([]);

			await expect(
				generateAuthenticationChallenge({ userId: 'user-123' })
			).rejects.toThrow();

			expect(createChallenge).not.toHaveBeenCalled();
		});

		it('throws INVALID_INPUT when userId is blank', async () => {
			await expect(
				generateAuthenticationChallenge({ userId: '   ' })
			).rejects.toMatchObject({
				name: 'PasskeyError',
				code: PasskeyErrorCode.INVALID_INPUT,
				message: 'userId must be a non-empty string when provided'
			});

			expect(getPasskeysByUserId).not.toHaveBeenCalled();
			expect(createChallenge).not.toHaveBeenCalled();
		});

		it('throws INVALID_PASSKEY_DATA when stored transports are malformed', async () => {
			vi.mocked(getPasskeysByUserId).mockResolvedValue([
				{
					id: 'pk-1',
					userId: 'user-123',
					credentialId: 'cred-aaa',
					publicKey: 'pk-data',
					counter: 5,
					transports: '{"bad":true}',
					deviceType: 'multiDevice',
					backedUp: true,
					createdAt: new Date(),
					lastUsedAt: null
				}
			]);

			await expect(
				generateAuthenticationChallenge({ userId: 'user-123' })
			).rejects.toMatchObject({
				name: 'PasskeyError',
				code: PasskeyErrorCode.INVALID_PASSKEY_DATA,
				message: 'Stored passkey transports are invalid',
				cause: expect.any(Error)
			});

			expect(createChallenge).not.toHaveBeenCalled();
		});
	});
});
